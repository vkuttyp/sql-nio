import NIOCore
import CosmoSQLCore
import Foundation

// ── TDS Token Stream Decoder ──────────────────────────────────────────────────
//
// Parses the token stream inside TDS_TABULAR packets into SQLRows.

struct TDSTokenDecoder {

    // Column metadata from the most recent COLMETADATA token
    private(set) var columns: [SQLColumn] = []

    // Working row buffer for the current result set
    private var currentRows: [SQLRow] = []

    // All completed result sets (flushed on COLMETADATA/DONE)
    private(set) var resultSets: [[SQLRow]] = []

    // First result set — convenience alias used by simple query callers
    var rows: [SQLRow] { resultSets.first ?? [] }

    // Rows-affected count from the DONE token (DONE_COUNT bit)
    private(set) var rowsAffected: Int = 0

    // Return status from RETURN statement in stored proc
    private(set) var returnStatus: Int?

    // Output parameters collected from RETURNVALUE tokens
    private(set) var outputParameters: [String: SQLValue] = [:]

    // INFO/PRINT messages collected during decode
    private(set) var infoMessages: [(code: Int, message: String)] = []

    // Set when a server error token is encountered
    private(set) var serverError: SQLError?

    // SSPI token data (NTLM challenge) received from server during NTLM auth handshake
    private(set) var sspiData: [UInt8]?

    // Transaction descriptor from ENVCHANGE type 8 (BeginTransaction).
    // nil means no transaction change was observed in this response.
    private(set) var transactionDescriptor: UInt64?

    // MARK: - Entry point

    /// Feed a complete TDS tabular-result payload (without the 8-byte packet header).
    mutating func decode(buffer: inout ByteBuffer) throws {
        while buffer.readableBytes > 0 {
            guard let tokenByte: UInt8 = buffer.readInteger() else { break }
            guard let token = TDSTokenType(rawValue: tokenByte) else {
                throw TDSError.unknownTokenType(tokenByte)
            }
            try decodeToken(token, buffer: &buffer)
        }
    }

    /// Incrementally decode tokens from a partial buffer.
    /// Returns rows decoded in this call. Leaves the reader index at the first
    /// byte of any incomplete token so the caller can prepend more data and retry.
    mutating func decodePartial(buffer: inout ByteBuffer) -> [SQLRow] {
        var newRows: [SQLRow] = []
        while buffer.readableBytes > 0 {
            let savedIndex = buffer.readerIndex
            guard let tokenByte: UInt8 = buffer.readInteger() else { break }
            guard let token = TDSTokenType(rawValue: tokenByte) else {
                buffer.moveReaderIndex(to: savedIndex)
                break
            }
            let countBefore = currentRows.count
            do {
                try decodeToken(token, buffer: &buffer)
            } catch {
                // Incomplete — rewind to before the token byte and stop
                buffer.moveReaderIndex(to: savedIndex)
                break
            }
            let countAfter = currentRows.count
            if countAfter > countBefore {
                newRows.append(contentsOf: currentRows[countBefore..<countAfter])
            }
        }
        return newRows
    }

    // MARK: - Token dispatch

    private mutating func decodeToken(_ token: TDSTokenType, buffer: inout ByteBuffer) throws {
        switch token {
        case .colMetadata:  try decodeColMetadata(&buffer)
        case .row:          try decodeRow(&buffer)
        case .nbcRow:       try decodeNbcRow(&buffer)
        case .done, .doneProc, .doneInProc:
            try decodeDone(&buffer)
        case .error:        try decodeError(&buffer)
        case .info:         try decodeInfo(&buffer)
        case .envChange:    try decodeEnvChange(&buffer)
        case .loginAck:     try decodeLoginAck(&buffer)
        case .returnStatus: try decodeReturnStatus(&buffer)
        case .returnValue:  try decodeReturnValue(&buffer)
        case .orderBy:      try decodeOrderBy(&buffer)
        case .featureExtAck: try decodeFeatureExtAck(&buffer)
        case .colInfo, .tabName:
            // COLINFO (0x61) and TABNAME (0xA4) are variable-length tokens sent alongside
            // TEXT/NTEXT/IMAGE result sets. We skip them: read the 2-byte length then skip.
            guard let len: UInt16 = buffer.readInteger(endianness: .little) else { throw TDSError.incomplete }
            buffer.moveReaderIndex(forwardBy: Int(len))
        case .sspi:
            // SSPI token (0xED): 2-byte length + NTLM challenge blob.
            guard let len: UInt16 = buffer.readInteger(endianness: .little) else { throw TDSError.incomplete }
            guard let bytes = buffer.readBytes(length: Int(len)) else { throw TDSError.incomplete }
            sspiData = bytes
        }
    }

    // MARK: - COLMETADATA (0x81)

    private mutating func decodeColMetadata(_ buf: inout ByteBuffer) throws {
        guard let count: UInt16 = buf.readInteger(endianness: .little) else {
            throw TDSError.incomplete
        }
        if count == 0xFFFF {
            // No metadata (result-less query)
            columns = []
            return
        }
        // Flush any rows accumulated from a prior result set before starting a new one
        if !currentRows.isEmpty {
            resultSets.append(currentRows)
            currentRows = []
        }
        columns = []
        for _ in 0..<count {
            // UserType (4 bytes in TDS 7.2+), Flags (2 bytes), TypeInfo
            guard
                buf.readInteger(endianness: .little) as UInt32? != nil,  // userType
                buf.readInteger(endianness: .little) as UInt16? != nil   // flags
            else { throw TDSError.incomplete }

            let (typeID, scale) = try readTypeInfo(&buf)
            let name = try readBVarChar(&buf)   // B_VARCHAR: 1-byte length in chars + UTF-16LE
            columns.append(SQLColumn(name: name, dataTypeID: UInt32(typeID), scale: scale))
        }
    }

    // MARK: - ROW (0xD1)

    private mutating func decodeRow(_ buf: inout ByteBuffer) throws {
        var values: [SQLValue] = []
        for col in columns {
            let v = try readValue(typeID: UInt8(col.dataTypeID ?? 0), scale: col.scale, buf: &buf)
            values.append(v)
        }
        currentRows.append(SQLRow(columns: columns, values: values))
    }

    // MARK: - NBC ROW (0xD2) – Null Bitmap Compressed Row

    private mutating func decodeNbcRow(_ buf: inout ByteBuffer) throws {
        let bitmapLen = (columns.count + 7) / 8
        // Use a zero-copy slice instead of readBytes() to avoid heap-allocating a [UInt8].
        guard let bitmapSlice = buf.readSlice(length: bitmapLen) else {
            throw TDSError.incomplete
        }

        var values: [SQLValue] = []
        for (i, col) in columns.enumerated() {
            let byteIdx = bitmapSlice.readerIndex + i / 8
            let bitIdx  = i % 8
            let isNull  = ((bitmapSlice.getInteger(at: byteIdx, as: UInt8.self) ?? 0) >> bitIdx) & 0x01 == 1
            if isNull {
                values.append(.null)
            } else {
                let v = try readValue(typeID: UInt8(col.dataTypeID ?? 0), scale: col.scale, buf: &buf)
                values.append(v)
            }
        }
        currentRows.append(SQLRow(columns: columns, values: values))
    }

    // MARK: - DONE (0xFD/FE/FF)

    private mutating func decodeDone(_ buf: inout ByteBuffer) throws {
        guard
            let status: UInt16 = buf.readInteger(endianness: .little),
            let _: UInt16 = buf.readInteger(endianness: .little),   // curCmd
            let count: UInt64 = buf.readInteger(endianness: .little) // rowCount (8 bytes in TDS 7.2+)
        else { throw TDSError.incomplete }
        // Flush current rows into resultSets on any DONE token
        if !currentRows.isEmpty {
            resultSets.append(currentRows)
            currentRows = []
        }
        // Only trust the rowcount when the DONE_COUNT bit (0x10) is set
        if status & 0x10 != 0 {
            rowsAffected = Int(count)
        }
    }

    // MARK: - ERROR (0xAA)

    private mutating func decodeError(_ buf: inout ByteBuffer) throws {
        // Read the entire token body as a slice using the length field.
        guard
            let length: UInt16 = buf.readInteger(endianness: .little),
            var body = buf.readSlice(length: Int(length))
        else { throw TDSError.incomplete }

        guard
            let number: Int32 = body.readInteger(endianness: .little),
            let state:  UInt8 = body.readInteger(),
            let _:      UInt8 = body.readInteger()   // severity/class
        else { throw TDSError.incomplete }

        // MsgText is US_VARCHAR: 2-byte char count + UTF-16LE chars
        let message = readUSVarChar(&body)
        serverError = .serverError(code: Int(number), message: message, state: state)
        // Remaining bytes in body (ServerName, ProcName, LineNumber) are skipped
        // automatically when body goes out of scope.
    }

    // MARK: - INFO (0xAB) – same wire layout as ERROR, informational

    private mutating func decodeInfo(_ buf: inout ByteBuffer) throws {
        guard
            let length: UInt16 = buf.readInteger(endianness: .little),
            var body = buf.readSlice(length: Int(length))
        else { throw TDSError.incomplete }
        guard
            let number: Int32 = body.readInteger(endianness: .little),
            let _: UInt8 = body.readInteger(),   // state
            let _: UInt8 = body.readInteger()    // class
        else { return }
        let message = readUSVarChar(&body)
        infoMessages.append((Int(number), message))
    }

    // MARK: - ENVCHANGE (0xE3)

    private mutating func decodeEnvChange(_ buf: inout ByteBuffer) throws {
        guard
            let length: UInt16 = buf.readInteger(endianness: .little),
            var body = buf.readSlice(length: Int(length))
        else { throw TDSError.incomplete }
        guard let changeType: UInt8 = body.readInteger() else { return }
        switch changeType {
        case 8:  // BeginTransaction — NewValue = 8-byte transaction descriptor
            guard let newLen: UInt8 = body.readInteger(), newLen == 8,
                  let descriptor: UInt64 = body.readInteger(endianness: .little)
            else { return }
            transactionDescriptor = descriptor
        case 9, 10:  // CommitTransaction / RollbackTransaction — descriptor resets to 0
            transactionDescriptor = 0
        default:
            break  // Other env changes (database, language, etc.) — ignore
        }
    }

    // MARK: - LOGINACK (0xAD)

    private mutating func decodeLoginAck(_ buf: inout ByteBuffer) throws {
        guard let length: UInt16 = buf.readInteger(endianness: .little) else {
            throw TDSError.incomplete
        }
        buf.moveReaderIndex(forwardBy: Int(length))
    }

    // MARK: - Misc tokens

    private mutating func decodeReturnStatus(_ buf: inout ByteBuffer) throws {
        guard let status: Int32 = buf.readInteger(endianness: .little) else {
            throw TDSError.incomplete
        }
        returnStatus = Int(status)
    }

    /// RETURNVALUE (0xAC) — output parameter value from a stored procedure.
    private mutating func decodeReturnValue(_ buf: inout ByteBuffer) throws {
        guard
            let _: UInt16 = buf.readInteger(endianness: .little)   // param ordinal
        else { throw TDSError.incomplete }
        let paramName = try readBVarChar(&buf)
        guard
            let _: UInt8  = buf.readInteger(),                      // status flags
            let _: UInt32 = buf.readInteger(endianness: .little),   // userType
            let _: UInt16 = buf.readInteger(endianness: .little)    // flags
        else { throw TDSError.incomplete }
        let (typeID, scale) = try readTypeInfo(&buf)
        let value = try readValue(typeID: typeID, scale: scale, buf: &buf)
        outputParameters[paramName] = value
    }

    private func decodeOrderBy(_ buf: inout ByteBuffer) throws {
        guard let len: UInt16 = buf.readInteger(endianness: .little) else {
            throw TDSError.incomplete
        }
        buf.moveReaderIndex(forwardBy: Int(len))
    }
    private func decodeFeatureExtAck(_ buf: inout ByteBuffer) throws {
        // Variable length; scan for terminator 0xFF
        while let b: UInt8 = buf.readInteger(), b != 0xFF {
            guard let len: UInt32 = buf.readInteger(endianness: .little) else { break }
            buf.moveReaderIndex(forwardBy: Int(len))
        }
    }

    // MARK: - Type info helpers

    /// Reads the TypeInfo field and returns (typeID, length).
    private func readTypeInfo(_ buf: inout ByteBuffer) throws -> (typeID: UInt8, scale: UInt8) {
        guard let typeID: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
        switch typeID {
        // Fixed-length types (no extra TypeInfo bytes)
        case 0x1F, 0x30, 0x32, 0x34, 0x38, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x7A, 0x7F, 0x28:
            return (typeID, 0)
        // Variable-length: USHORTLEN types (MaxLength 2 bytes + optional 5-byte collation)
        case 0xA7, 0xAF, 0xA5, 0xAD, 0xE7:
            guard let maxLen: UInt16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            if typeID == 0xA7 || typeID == 0xAF || typeID == 0xE7 {
                buf.moveReaderIndex(forwardBy: 5)   // collation
            }
            // 0xFFFF = MAX type → PLP encoding in row data; signal with scale=0xFF
            return (typeID, maxLen == 0xFFFF ? 0xFF : 0)
        // BYTELENTYPE (maxLen byte in TypeInfo, length byte in row data)
        case 0x24, 0x26, 0x68, 0x6D, 0x6E, 0x6F:
            guard let _: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            return (typeID, 0)
        // Decimal/Numeric: maxLen + precision + scale
        case 0x6A, 0x6C:
            guard
                let _: UInt8 = buf.readInteger(),       // maxLen
                let _: UInt8 = buf.readInteger(),       // precision
                let s: UInt8 = buf.readInteger()        // scale
            else { throw TDSError.incomplete }
            return (typeID, s)
        // Time/DateTime2/DateTimeOffset: scale byte
        case 0x29, 0x2A, 0x2B:
            guard let s: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            return (typeID, s)
        // LONGLEN types (TEXT, NTEXT, IMAGE)
        // TypeInfo format (TDS 7.4):
        //   MaxLen: ULONG (4 bytes)
        //   Collation: 5 bytes — present for TEXT (0x23) and NTEXT (0x63), absent for IMAGE (0x22)
        //   TableName: NumParts BYTE + NumParts × US_VARCHAR (2-byte char count + UTF-16LE)
        case 0x23, 0x63, 0x22:
            buf.moveReaderIndex(forwardBy: 4)   // maxLen (ULONG)
            if typeID == 0x23 || typeID == 0x63 {
                buf.moveReaderIndex(forwardBy: 5)   // Collation (TEXT/NTEXT only)
            }
            // TableName: NumParts (1 byte) + each part as US_VARCHAR
            guard let numParts: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            for _ in 0..<numParts {
                guard let charCount: UInt16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                buf.moveReaderIndex(forwardBy: Int(charCount) * 2)   // UTF-16LE chars
            }
            return (typeID, 0)
        default:
            return (typeID, 0)
        }
    }

    // 1900-01-01 00:00:00 UTC as Unix timestamp (reference epoch for SQL Server DATETIME)
    private static let sqlServerEpoch: Double = -2208988800.0
    // 0001-01-01 00:00:00 UTC as Unix timestamp (reference epoch for DATE/DATETIME2/DATETIMEOFFSET)
    private static let dateEpoch: Int64 = -62135596800

    // MARK: - Value reading

    private func readValue(typeID: UInt8, scale: UInt8, buf: inout ByteBuffer) throws -> SQLValue {
        switch typeID {
        case 0x1F: return .null
        case 0x30:   // tinyint (fixed)
            guard let v: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            return .int(Int(v))
        case 0x32:   // bit (fixed)
            guard let v: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            return .bool(v != 0)
        case 0x34:   // smallint
            guard let v: Int16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .int(Int(v))
        case 0x38:   // int
            guard let v: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .int32(v)
        case 0x7F:   // bigint
            guard let v: Int64 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .int64(v)
        case 0x3B:   // real
            guard let v: UInt32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .float(Float(bitPattern: v))
        case 0x3E:   // float
            guard let v: UInt64 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .double(Double(bitPattern: v))
        case 0x26:   // intn (nullable int)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            switch len {
            case 1:
                guard let v: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
                return .int(Int(v))
            case 2:
                guard let v: Int16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .int(Int(v))
            case 4:
                guard let v: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .int32(v)
            case 8:
                guard let v: Int64 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .int64(v)
            default:
                buf.moveReaderIndex(forwardBy: Int(len))
                return .null
            }
        case 0x6D:   // floatn (nullable float)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            if len == 4 {
                guard let v: UInt32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .float(Float(bitPattern: v))
            } else {
                guard let v: UInt64 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .double(Double(bitPattern: v))
            }
        case 0x68:   // bitn (nullable bit)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard let v: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            return .bool(v != 0)
        case 0xE7, 0xA7, 0xAF, 0xA5, 0xAD:
            // MAX types use PLP (Partially Length-Prefixed) encoding (signalled by scale=0xFF).
            // Regular types use a 2-byte length prefix.
            if scale == 0xFF {
                return try readPLPValue(typeID: typeID, buf: &buf)
            }
            // US_VARCHAR: 2-byte length prefix (-1 = NULL)
            guard let len: Int16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            if len == -1 { return .null }
            let byteLen = Int(len)
            if typeID == 0xE7 {
                // nvarchar: UTF-16LE
                guard let bytes = buf.readBytes(length: byteLen) else { throw TDSError.incomplete }
                let str = String(bytes: bytes, encoding: .utf16LittleEndian) ?? ""
                return .string(str)
            } else {
                guard let str = buf.readString(length: byteLen) else { throw TDSError.incomplete }
                return .string(str)
            }
        case 0x24:   // uniqueidentifier (BYTELEN_TYPE: 1-byte len prefix in row)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard let bytes = buf.readBytes(length: 16) else { throw TDSError.incomplete }
            // SQL Server stores UUID in mixed-endian; convert to standard form
            let uuid = UUID(uuid: (bytes[3], bytes[2], bytes[1], bytes[0],
                                   bytes[5], bytes[4], bytes[7], bytes[6],
                                   bytes[8], bytes[9], bytes[10], bytes[11],
                                   bytes[12], bytes[13], bytes[14], bytes[15]))
            return .uuid(uuid)
        case 0x3D:   // datetime (fixed 8 bytes: 4-byte days + 4-byte 1/300s ticks)
            guard let days: Int32 = buf.readInteger(endianness: .little),
                  let ticks: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            let secs = Double(days) * 86400.0 + Double(ticks) / 300.0
            return .date(Date(timeIntervalSince1970: Self.sqlServerEpoch + secs))
        case 0x3A:   // smalldatetime (fixed 4 bytes: 2-byte days + 2-byte minutes)
            guard let days: UInt16 = buf.readInteger(endianness: .little),
                  let mins: UInt16 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            let secs = Double(days) * 86400.0 + Double(mins) * 60.0
            return .date(Date(timeIntervalSince1970: Self.sqlServerEpoch + secs))
        case 0x6F:   // datetimen (BYTELEN_TYPE: len=0→null, len=4→smalldatetime, len=8→datetime)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard let bytes = buf.readBytes(length: Int(len)) else { throw TDSError.incomplete }
            let secs: Double
            if len == 8 {
                let days = Int32(bytes[0]) | Int32(bytes[1]) << 8 | Int32(bytes[2]) << 16 | Int32(bytes[3]) << 24
                let ticks = Int32(bytes[4]) | Int32(bytes[5]) << 8 | Int32(bytes[6]) << 16 | Int32(bytes[7]) << 24
                secs = Double(days) * 86400.0 + Double(ticks) / 300.0
            } else {   // len == 4: smalldatetime
                let days = UInt16(bytes[0]) | UInt16(bytes[1]) << 8
                let mins = UInt16(bytes[2]) | UInt16(bytes[3]) << 8
                secs = Double(days) * 86400.0 + Double(mins) * 60.0
            }
            return .date(Date(timeIntervalSince1970: Self.sqlServerEpoch + secs))
        case 0x6A, 0x6C:   // decimal / numeric (BYTELEN_TYPE: sign byte + LE integer mantissa)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard len >= 1, let bytes = buf.readBytes(length: Int(len)) else { throw TDSError.incomplete }
            let positive = bytes[0] == 0x01
            // Build mantissa as Decimal using exact arithmetic (bytes are LE)
            var mantissa = Decimal(0)
            var mult     = Decimal(1)
            for i in 1..<bytes.count {
                mantissa += Decimal(bytes[i]) * mult
                mult     *= 256
            }
            // Apply scale by dividing by 10^scale
            var divisor = Decimal(1)
            for _ in 0..<scale { divisor *= 10 }
            var result = mantissa / divisor
            if !positive { result.negate() }
            return .decimal(result)
        case 0x3C:   // money (fixed 8 bytes: hi/lo INT32 pair, value × 10000)
            guard let hi: Int32 = buf.readInteger(endianness: .little),
                  let lo: UInt32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            let raw = (Int64(hi) << 32) | Int64(lo)
            return .decimal(Decimal(raw) / 10000)
        case 0x7A:   // smallmoney (fixed 4 bytes, value × 10000)
            guard let raw: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            return .decimal(Decimal(raw) / 10000)
        case 0x6E:   // moneyn (nullable MONEY/SMALLMONEY)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            if len == 4 {
                guard let raw: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                return .decimal(Decimal(raw) / 10000)
            } else {  // len == 8
                guard let hi: Int32  = buf.readInteger(endianness: .little),
                      let lo: UInt32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
                let raw = (Int64(hi) << 32) | Int64(lo)
                return .decimal(Decimal(raw) / 10000)
            }
        case 0x28:   // date (BYTELEN_TYPE: 3 bytes = days since 0001-01-01)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard let bytes = buf.readBytes(length: 3) else { throw TDSError.incomplete }
            let days = Int64(bytes[0]) | Int64(bytes[1]) << 8 | Int64(bytes[2]) << 16
            return .date(Date(timeIntervalSince1970: Double(Self.dateEpoch + days * 86400)))
        case 0x29:   // time (BYTELEN_TYPE, scale-dependent length, 100ns ticks since midnight)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            guard let bytes = buf.readBytes(length: Int(len)) else { throw TDSError.incomplete }
            var ticks: Int64 = 0
            for i in 0..<Int(len) { ticks |= Int64(bytes[i]) << (i * 8) }
            var divisor: Double = 1; for _ in 0..<scale { divisor *= 10 }
            return .date(Date(timeIntervalSince1970: Double(ticks) / divisor))
        case 0x2A:   // datetime2 (BYTELEN_TYPE: time portion + 3-byte date)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            let tLen = Int(len) - 3
            guard tLen > 0,
                  let tBytes = buf.readBytes(length: tLen),
                  let dBytes = buf.readBytes(length: 3) else { throw TDSError.incomplete }
            var ticks: Int64 = 0
            for i in 0..<tLen { ticks |= Int64(tBytes[i]) << (i * 8) }
            var divisor: Double = 1; for _ in 0..<scale { divisor *= 10 }
            let timeSecs = Double(ticks) / divisor
            let days2 = Int64(dBytes[0]) | Int64(dBytes[1]) << 8 | Int64(dBytes[2]) << 16
            return .date(Date(timeIntervalSince1970: Double(Self.dateEpoch + days2 * 86400) + timeSecs))
        case 0x2B:   // datetimeoffset (BYTELEN_TYPE: DATETIME2 + 2-byte UTC offset in minutes)
            guard let len: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if len == 0 { return .null }
            let tLen = Int(len) - 5  // time bytes = total - 3 date - 2 offset
            guard tLen > 0,
                  let tBytes = buf.readBytes(length: tLen),
                  let dBytes = buf.readBytes(length: 3),
                  let oBytes = buf.readBytes(length: 2) else { throw TDSError.incomplete }
            var ticks: Int64 = 0
            for i in 0..<tLen { ticks |= Int64(tBytes[i]) << (i * 8) }
            var divisor: Double = 1; for _ in 0..<scale { divisor *= 10 }
            let timeSecs2 = Double(ticks) / divisor
            let days3 = Int64(dBytes[0]) | Int64(dBytes[1]) << 8 | Int64(dBytes[2]) << 16
            let offsetMins = Int16(bitPattern: UInt16(oBytes[0]) | UInt16(oBytes[1]) << 8)
            // SQL Server stores DATETIMEOFFSET with UTC date+time on the wire;
            // the offset is informational only — do NOT subtract it again.
            _ = offsetMins
            return .date(Date(timeIntervalSince1970: Double(Self.dateEpoch + days3 * 86400) + timeSecs2))
        case 0x23, 0x63, 0x22:  // TEXT(0x23), NTEXT(0x63), IMAGE(0x22) — LONGLEN row format
            // TextPtrLen byte: 0 = NULL
            guard let textPtrLen: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
            if textPtrLen == 0 { return .null }
            // Skip TextPtr (textPtrLen bytes) + 8-byte timestamp
            buf.moveReaderIndex(forwardBy: Int(textPtrLen) + 8)
            // DataLen: -1 = NULL
            guard let dataLen: Int32 = buf.readInteger(endianness: .little) else { throw TDSError.incomplete }
            if dataLen < 0 { return .null }
            guard let bytes = buf.readBytes(length: Int(dataLen)) else { throw TDSError.incomplete }
            switch typeID {
            case 0x63:  // NTEXT: UTF-16LE
                return .string(String(bytes: bytes, encoding: .utf16LittleEndian) ?? "")
            case 0x22:  // IMAGE: binary
                return .bytes(bytes)
            default:    // TEXT: UTF-8 (with Windows-1252 fallback)
                return .string(String(bytes: bytes, encoding: .utf8)
                    ?? String(bytes: bytes, encoding: .windowsCP1252)
                    ?? "")
            }
        default:
            // Unknown/unhandled type – return null
            return .null
        }
    }

    // MARK: - PLP (Partially Length-Prefixed) helper for MAX types

    /// Reads a PLP-encoded value (NVARCHAR(MAX), VARCHAR(MAX), VARBINARY(MAX)).
    /// PLP format: 8-byte total length (0xFFFF…FF = null, 0 = empty),
    /// then chunks: 4-byte chunk length + chunk bytes, terminated by 4-byte 0.
    private func readPLPValue(typeID: UInt8, buf: inout ByteBuffer) throws -> SQLValue {
        guard let totalLen: UInt64 = buf.readInteger(endianness: .little) else {
            throw TDSError.incomplete
        }
        if totalLen == 0xFFFFFFFFFFFFFFFF { return .null }  // PLP_NULL

        var allBytes: [UInt8] = []
        if totalLen != 0xFFFFFFFFFFFFFFFE {   // known length → pre-size
            allBytes.reserveCapacity(Int(min(totalLen, 1_048_576)))
        }
        while true {
            guard let chunkLen: UInt32 = buf.readInteger(endianness: .little) else {
                throw TDSError.incomplete
            }
            if chunkLen == 0 { break }   // PLP terminator
            guard let chunk = buf.readBytes(length: Int(chunkLen)) else {
                throw TDSError.incomplete
            }
            allBytes.append(contentsOf: chunk)
        }

        if allBytes.isEmpty { return typeID == 0xA5 || typeID == 0xAD ? .bytes([]) : .string("") }
        if typeID == 0xE7 {
            return .string(String(bytes: allBytes, encoding: .utf16LittleEndian) ?? "")
        } else if typeID == 0xA5 || typeID == 0xAD {
            return .bytes(allBytes)
        } else {
            return .string(String(bytes: allBytes, encoding: .utf8) ?? "")
        }
    }

    // MARK: - String helpers

    /// Reads a US_VARCHAR: 2-byte character count (little-endian), then UTF-16LE string.
    private func readUSVarChar(_ buf: inout ByteBuffer) -> String {
        guard let charCount: UInt16 = buf.readInteger(endianness: .little) else { return "" }
        let byteCount = Int(charCount) * 2
        guard byteCount > 0, let bytes = buf.readBytes(length: byteCount) else { return "" }
        return String(bytes: bytes, encoding: .utf16LittleEndian) ?? ""
    }

    /// Reads a B_VARCHAR: 1-byte character count, then UTF-16LE encoded string.
    private func readBVarChar(_ buf: inout ByteBuffer) throws -> String {
        guard let charCount: UInt8 = buf.readInteger() else { throw TDSError.incomplete }
        let byteCount = Int(charCount) * 2
        if byteCount == 0 { return "" }
        guard let bytes = buf.readBytes(length: byteCount) else { throw TDSError.incomplete }
        return String(bytes: bytes, encoding: .utf16LittleEndian) ?? ""
    }
}
