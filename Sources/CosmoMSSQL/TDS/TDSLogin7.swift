import NIOCore
import Foundation

// ── TDS Login7 ────────────────────────────────────────────────────────────────
//
// Sent after TLS is established (or skipped) to authenticate.
// Reference: MS-TDS §2.2.6.4

struct TDSLogin7 {
    // Fixed header fields
    var tdsVersion:        UInt32 = 0x74000004   // TDS 7.4
    var packetSize:        UInt32 = 32768
    var clientProgVer:     UInt32 = 0x07000000
    var clientPID:         UInt32 = UInt32(ProcessInfo.processInfo.processIdentifier)
    var connectionID:      UInt32 = 0
    var optionFlags1:      UInt8  = 0xE0
    var optionFlags2:      UInt8  = 0x03
    var typeFlags:         UInt8  = 0x00
    var optionFlags3:      UInt8  = 0x00
    var clientTimezone:    Int32  = 0
    var clientLCID:        UInt32 = 0x0409   // en-US

    // Variable-length fields
    var hostname:    String
    var username:    String
    var password:    String
    var appName:     String  = "sql-nio"
    var serverName:  String
    var libraryName: String  = "sql-nio/1.0"
    var language:    String  = ""
    var database:    String
    /// SSPI blob for NTLM/Windows authentication (NTLM_NEGOTIATE message).
    var sspiData:    [UInt8] = []

    init(username: String, password: String, hostname: String,
         serverName: String, database: String, readOnly: Bool = false) {
        self.username   = username
        self.password   = password
        self.hostname   = hostname
        self.serverName = serverName
        self.database   = database
        if readOnly {
            // typeFlags bit 5 = fReadOnlyIntent (ApplicationIntent=ReadOnly)
            self.typeFlags |= 0x20
        }
    }

    func encode(allocator: ByteBufferAllocator) -> ByteBuffer {
        let scrambled = encodePassword(password)

        // Fixed part size: 4+4+4+4+4+1+1+1+1+4+4 + 36 offset/len pairs (each 2+2) + ClientID (6) = 36 + 4 (totalLen) + 48 + 6 = 94
        let fixedSize = 94
        var offsetBuf = allocator.buffer(capacity: fixedSize)
        var dataBuf   = allocator.buffer(capacity: 256)

        func writeOffsetLen(_ str: String) {
            let offset = UInt16(fixedSize + dataBuf.writerIndex)
            let utf16  = Array(str.utf16)
            offsetBuf.writeInteger(offset, endianness: .little)
            offsetBuf.writeInteger(UInt16(utf16.count), endianness: .little)
            for unit in utf16 { dataBuf.writeInteger(unit, endianness: .little) }
        }

        // Offsets block
        writeOffsetLen(hostname)
        writeOffsetLen(username)
        // Password: offset/len
        let pwdOffset = UInt16(fixedSize + dataBuf.writerIndex)
        offsetBuf.writeInteger(pwdOffset, endianness: .little)
        // cchPassword is in characters (UTF-16 code units), not bytes
        offsetBuf.writeInteger(UInt16(password.utf16.count), endianness: .little)
        dataBuf.writeBytes(scrambled)

        writeOffsetLen(appName)
        writeOffsetLen(serverName)
        writeOffsetLen("")   // extension
        writeOffsetLen(libraryName)
        writeOffsetLen(language)
        writeOffsetLen(database)
        // ClientID (6 bytes MAC-like)
        offsetBuf.writeBytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        // SSPI: offset + length
        if sspiData.isEmpty {
            writeOffsetLen("")
        } else {
            let sspiOffset = UInt16(fixedSize + dataBuf.writerIndex)
            offsetBuf.writeInteger(sspiOffset, endianness: .little)
            offsetBuf.writeInteger(UInt16(sspiData.count), endianness: .little)
            dataBuf.writeBytes(sspiData)
        }
        writeOffsetLen("")   // attachDB
        writeOffsetLen("")   // newPassword
        // SSPI long (4 bytes) — used only when SSPI > 65535 bytes
        offsetBuf.writeInteger(UInt32(0), endianness: .little)

        let totalLength = UInt32(fixedSize + dataBuf.writerIndex)

        var out = allocator.buffer(capacity: Int(totalLength))
        out.writeInteger(totalLength,     endianness: .little)
        out.writeInteger(tdsVersion,      endianness: .little)
        out.writeInteger(packetSize,      endianness: .little)
        out.writeInteger(clientProgVer,   endianness: .little)
        out.writeInteger(clientPID,       endianness: .little)
        out.writeInteger(connectionID,    endianness: .little)
        out.writeInteger(optionFlags1)
        out.writeInteger(optionFlags2)
        out.writeInteger(typeFlags)
        out.writeInteger(optionFlags3)
        out.writeInteger(clientTimezone,  endianness: .little)
        out.writeInteger(clientLCID,      endianness: .little)
        out.writeBuffer(&offsetBuf)
        out.writeBuffer(&dataBuf)
        return out
    }

    // MARK: - Password scrambling (MS-TDS §2.2.6.4)
    // Algorithm: for each UTF-16LE byte — nibble-swap first, then XOR with 0xA5.
    private func encodePassword(_ raw: String) -> [UInt8] {
        var result: [UInt8] = []
        for unit in raw.utf16 {
            let lo = UInt8(unit & 0xFF)
            let hi = UInt8((unit >> 8) & 0xFF)
            result.append(((lo & 0x0F) << 4 | (lo & 0xF0) >> 4) ^ 0xA5)
            result.append(((hi & 0x0F) << 4 | (hi & 0xF0) >> 4) ^ 0xA5)
        }
        return result
    }
}
