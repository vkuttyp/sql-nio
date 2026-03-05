import NIOCore
import CosmoSQLCore
import Foundation

// ── TDS RPC Request (sp_executesql) ──────────────────────────────────────────
//
// Encodes a parameterized query as a native TDS RPC packet (type 0x03).
// This sends parameters as typed binary values — they never appear in the SQL
// text, making them immune to SQL injection and enabling query-plan caching.
//
// Wire format for sp_executesql (procID=10):
//   ALL_HEADERS (22 bytes)
//   0xFFFF + 0x000A         ← well-known proc ID for sp_executesql
//   0x0000                  ← option flags
//   --- Param 1: @stmt ---
//   name=""  flags=0  typeInfo=NVARCHAR(MAX)  PLPvalue(sql)
//   --- Param 2: @params ---
//   name=""  flags=0  typeInfo=NVARCHAR(MAX)  PLPvalue(decl)
//   --- Param 3+ ---
//   name="@p1" flags=0  typeInfo  value

struct TDSRPCRequest {

    let sql: String
    let binds: [SQLValue]

    // MARK: - Public entry point

    /// Returns true when there are parameters to bind (use RPC path).
    var hasBinds: Bool { !binds.isEmpty }

    /// Encode the sp_executesql RPC request body (everything after the 8-byte TDS packet header).
    func encode(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buf = allocator.buffer(capacity: 512)

        // ALL_HEADERS block (22 bytes) — same as SQL batch
        buf.writeInteger(UInt32(22), endianness: .little)   // total length
        buf.writeInteger(UInt32(18), endianness: .little)   // header length
        buf.writeInteger(UInt16(2),  endianness: .little)   // type = TRANSACTION_DESCRIPTOR
        buf.writeInteger(UInt64(0),  endianness: .little)   // transaction descriptor
        buf.writeInteger(UInt32(1),  endianness: .little)   // outstanding request count

        // Proc ID reference: 0xFFFF = well-known proc, then 0x000A = sp_executesql
        buf.writeInteger(UInt16(0xFFFF), endianness: .little)
        buf.writeInteger(UInt16(10),     endianness: .little)   // SP_EXECUTESQL = 10

        // Option flags: none
        buf.writeInteger(UInt16(0), endianness: .little)

        // Build the parameter declaration string: "@p1 INT, @p2 NVARCHAR(MAX), ..."
        let decl = binds.enumerated().map { (i, v) in
            "@p\(i+1) \(v.tdsTypeName)"
        }.joined(separator: ", ")

        // Param 1: @stmt — the SQL text (unnamed, NVARCHAR(MAX) PLP)
        writeNVarCharMaxParam(name: "", value: sql, into: &buf)

        // Param 2: @params — declaration string (unnamed, NVARCHAR(MAX) PLP)
        writeNVarCharMaxParam(name: "", value: decl, into: &buf)

        // Param 3+: @p1, @p2, ... with typed binary values
        for (i, bind) in binds.enumerated() {
            writeParam(name: "@p\(i+1)", value: bind, into: &buf)
        }

        return buf
    }

    /// Write an NVARCHAR(MAX) parameter using PLP encoding.
    private func writeNVarCharMaxParam(name: String, value: String, into buf: inout ByteBuffer) {
        // B_VARCHAR name: 1-byte char count + UTF-16LE
        writeBVarChar(name, into: &buf)
        buf.writeInteger(UInt8(0))   // StatusFlags: normal

        // TypeInfo: NVARCHAR (0xE7), maxLen=0xFFFF (MAX), 5-byte collation
        buf.writeInteger(UInt8(0xE7))
        buf.writeInteger(UInt16(0xFFFF), endianness: .little)
        buf.writeBytes([0x09, 0x04, 0x10, 0x00, 0x00])   // Latin1_General_CI_AS

        // PLP value
        writePLPString(value, into: &buf)
    }

    /// Write a typed parameter value with its TypeInfo.
    private func writeParam(name: String, value: SQLValue, into buf: inout ByteBuffer) {
        writeBVarChar(name, into: &buf)
        buf.writeInteger(UInt8(0))   // StatusFlags: normal

        switch value {
        case .null:
            // Send as INTN(4) with len=0
            buf.writeInteger(UInt8(0x26))   // INTN
            buf.writeInteger(UInt8(4))       // maxLen
            buf.writeInteger(UInt8(0))       // actual len = 0 (NULL)

        case .bool(let v):
            buf.writeInteger(UInt8(0x68))   // BITN
            buf.writeInteger(UInt8(1))       // maxLen
            buf.writeInteger(UInt8(1))       // actual len
            buf.writeInteger(UInt8(v ? 1 : 0))

        case .int(let v):
            buf.writeInteger(UInt8(0x26))   // INTN
            buf.writeInteger(UInt8(8))       // maxLen
            buf.writeInteger(UInt8(8))       // actual len
            buf.writeInteger(Int64(v), endianness: .little)

        case .int8(let v):
            buf.writeInteger(UInt8(0x26))
            buf.writeInteger(UInt8(1))
            buf.writeInteger(UInt8(1))
            buf.writeInteger(UInt8(bitPattern: v))

        case .int16(let v):
            buf.writeInteger(UInt8(0x26))
            buf.writeInteger(UInt8(2))
            buf.writeInteger(UInt8(2))
            buf.writeInteger(v, endianness: .little)

        case .int32(let v):
            buf.writeInteger(UInt8(0x26))
            buf.writeInteger(UInt8(4))
            buf.writeInteger(UInt8(4))
            buf.writeInteger(v, endianness: .little)

        case .int64(let v):
            buf.writeInteger(UInt8(0x26))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(v, endianness: .little)

        case .float(let v):
            buf.writeInteger(UInt8(0x6D))   // FLOATN
            buf.writeInteger(UInt8(4))       // maxLen
            buf.writeInteger(UInt8(4))       // actual len
            buf.writeInteger(v.bitPattern, endianness: .little)

        case .double(let v):
            buf.writeInteger(UInt8(0x6D))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(v.bitPattern, endianness: .little)

        case .string(let v):
            // NVARCHAR(MAX) TypeInfo + PLP value
            buf.writeInteger(UInt8(0xE7))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            buf.writeBytes([0x09, 0x04, 0x10, 0x00, 0x00])   // Latin1_General_CI_AS
            writePLPString(v, into: &buf)

        case .decimal(let v):
            let str = (v as NSDecimalNumber).stringValue
            buf.writeInteger(UInt8(0xE7))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            buf.writeBytes([0x09, 0x04, 0x10, 0x00, 0x00])
            writePLPString(str, into: &buf)

        case .bytes(let v):
            buf.writeInteger(UInt8(0xA5))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            writePLPBytes(v, into: &buf)

        case .uuid(let v):
            buf.writeInteger(UInt8(0x24))   // GUIDTYPE
            buf.writeInteger(UInt8(16))      // maxLen
            buf.writeInteger(UInt8(16))      // actual len
            writeUUIDMixedEndian(v, into: &buf)

        case .date(let v):
            buf.writeInteger(UInt8(0x6F))   // DATETIMN
            buf.writeInteger(UInt8(8))       // maxLen
            buf.writeInteger(UInt8(8))       // actual len
            let epoch: Double = -2208988800.0
            let secs = v.timeIntervalSince1970 - epoch
            let days  = Int32(secs / 86400)
            let ticks = Int32((secs.truncatingRemainder(dividingBy: 86400)) * 300)
            buf.writeInteger(days,  endianness: .little)
            buf.writeInteger(ticks, endianness: .little)
        }
    }

    // MARK: - PLP helpers

    private func writePLPString(_ s: String, into buf: inout ByteBuffer) {
        let utf16 = Array(s.utf16)
        let byteLen = utf16.count * 2
        if byteLen == 0 {
            buf.writeInteger(UInt64(0), endianness: .little)
            buf.writeInteger(UInt32(0), endianness: .little)
            return
        }
        buf.writeInteger(UInt64(byteLen), endianness: .little)
        buf.writeInteger(UInt32(byteLen), endianness: .little)
        for unit in utf16 {
            buf.writeInteger(UInt8(unit & 0xFF))
            buf.writeInteger(UInt8((unit >> 8) & 0xFF))
        }
        buf.writeInteger(UInt32(0), endianness: .little)
    }

    private func writePLPBytes(_ bytes: [UInt8], into buf: inout ByteBuffer) {
        if bytes.isEmpty {
            buf.writeInteger(UInt64(0), endianness: .little)
            buf.writeInteger(UInt32(0), endianness: .little)
            return
        }
        buf.writeInteger(UInt64(bytes.count), endianness: .little)
        buf.writeInteger(UInt32(bytes.count), endianness: .little)
        buf.writeBytes(bytes)
        buf.writeInteger(UInt32(0), endianness: .little)
    }

    // MARK: - String helpers

    private func writeBVarChar(_ s: String, into buf: inout ByteBuffer) {
        let utf16 = Array(s.utf16)
        buf.writeInteger(UInt8(utf16.count))
        for unit in utf16 {
            buf.writeInteger(UInt8(unit & 0xFF))
            buf.writeInteger(UInt8((unit >> 8) & 0xFF))
        }
    }

    // MARK: - UUID mixed-endian (SQL Server format)

    private func writeUUIDMixedEndian(_ uuid: UUID, into buf: inout ByteBuffer) {
        let b = uuid.uuid
        // First 4 bytes reversed, next 2 reversed, next 2 reversed, last 8 as-is
        buf.writeBytes([b.3, b.2, b.1, b.0,
                        b.5, b.4, b.7, b.6,
                        b.8, b.9, b.10, b.11,
                        b.12, b.13, b.14, b.15])
    }
}

// MARK: - SQLValue type name for sp_executesql @params declaration

extension SQLValue {
    var tdsTypeName: String {
        switch self {
        case .null:    return "INT"
        case .bool:    return "BIT"
        case .int:     return "BIGINT"
        case .int8:    return "TINYINT"
        case .int16:   return "SMALLINT"
        case .int32:   return "INT"
        case .int64:   return "BIGINT"
        case .float:   return "REAL"
        case .double:  return "FLOAT(53)"
        case .decimal: return "NVARCHAR(50)"
        case .string:  return "NVARCHAR(MAX)"
        case .bytes:   return "VARBINARY(MAX)"
        case .uuid:    return "UNIQUEIDENTIFIER"
        case .date:    return "DATETIME"
        }
    }
}
