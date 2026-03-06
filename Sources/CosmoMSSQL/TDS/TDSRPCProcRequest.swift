import NIOCore
import CosmoSQLCore
import Foundation

// ── TDS RPC Request for Named Stored Procedures ──────────────────────────────
//
// Encodes a TDS RPC packet (type 0x03) for calling a named stored procedure
// directly, supporting both INPUT and OUTPUT parameters.
//
// Wire format:
//   ALL_HEADERS (22 bytes)
//   ProcNameLength: USHORT (char count)
//   ProcName:       UTF-16LE
//   OptionFlags:    USHORT = 0
//   [Parameters: name + statusFlags + typeInfo + value ...]

struct TDSRPCProcRequest {

    let procName:   String
    let parameters: [SQLParameter]

    // MARK: - Encode

    func encode(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buf = allocator.buffer(capacity: 256)

        // ALL_HEADERS block (22 bytes)
        buf.writeInteger(UInt32(22), endianness: .little)
        buf.writeInteger(UInt32(18), endianness: .little)
        buf.writeInteger(UInt16(2),  endianness: .little)   // TRANSACTION_DESCRIPTOR
        buf.writeInteger(UInt64(0),  endianness: .little)   // transaction descriptor
        buf.writeInteger(UInt32(1),  endianness: .little)   // outstanding request count

        // Procedure name reference (not a well-known proc ID)
        let nameUTF16 = Array(procName.utf16)
        buf.writeInteger(UInt16(nameUTF16.count), endianness: .little)
        for unit in nameUTF16 { buf.writeInteger(unit, endianness: .little) }

        // Option flags: none
        buf.writeInteger(UInt16(0), endianness: .little)

        // Parameters
        for param in parameters {
            writeParam(param, into: &buf)
        }

        return buf
    }

    // MARK: - Parameter encoding

    private func writeParam(_ param: SQLParameter, into buf: inout ByteBuffer) {
        writeBVarChar(param.name, into: &buf)
        // StatusFlags: 0x00 = input, 0x01 = output
        buf.writeInteger(UInt8(param.isOutput ? 0x01 : 0x00))

        switch param.value {
        case .null:
            // Default output/unknown params → nullable INT
            buf.writeInteger(UInt8(0x26))   // INTN
            buf.writeInteger(UInt8(4))       // maxLen
            buf.writeInteger(UInt8(0))       // actualLen = 0 (NULL)

        case .bool(let v):
            buf.writeInteger(UInt8(0x68))   // BITN
            buf.writeInteger(UInt8(1))
            buf.writeInteger(UInt8(1))
            buf.writeInteger(UInt8(v ? 1 : 0))

        case .int(let v):
            buf.writeInteger(UInt8(0x26))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(UInt8(8))
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
            buf.writeInteger(UInt8(4))
            buf.writeInteger(UInt8(4))
            buf.writeInteger(v.bitPattern, endianness: .little)

        case .double(let v):
            buf.writeInteger(UInt8(0x6D))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(UInt8(8))
            buf.writeInteger(v.bitPattern, endianness: .little)

        case .decimal(let v):
            // Send as NVARCHAR string — avoids need to know precision/scale ahead of time
            let str = (v as NSDecimalNumber).stringValue
            buf.writeInteger(UInt8(0xE7))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            buf.writeBytes([0x09, 0x04, 0x10, 0x00, 0x00])
            writePLPString(str, into: &buf)

        case .string(let v):
            buf.writeInteger(UInt8(0xE7))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            buf.writeBytes([0x09, 0x04, 0x10, 0x00, 0x00])
            writePLPString(v, into: &buf)

        case .bytes(let v):
            buf.writeInteger(UInt8(0xA5))
            buf.writeInteger(UInt16(0xFFFF), endianness: .little)
            writePLPBytes(v, into: &buf)

        case .uuid(let v):
            buf.writeInteger(UInt8(0x24))
            buf.writeInteger(UInt8(16))
            buf.writeInteger(UInt8(16))
            writeUUIDMixedEndian(v, into: &buf)

        case .date(let v):
            buf.writeInteger(UInt8(0x6F))   // DATETIMN
            buf.writeInteger(UInt8(8))
            buf.writeInteger(UInt8(8))
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
        for unit in utf16 { buf.writeInteger(unit, endianness: .little) }
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

    private func writeBVarChar(_ s: String, into buf: inout ByteBuffer) {
        var name = s
        if !name.isEmpty && !name.hasPrefix("@") {
            name = "@" + name
        }
        let utf16 = Array(name.utf16)
        // RPCParamName: 1-byte CHARACTER count prefix
        buf.writeInteger(UInt8(utf16.count))
        for unit in utf16 { buf.writeInteger(unit, endianness: .little) }
    }

    private func writeUUIDMixedEndian(_ uuid: UUID, into buf: inout ByteBuffer) {
        let b = uuid.uuid
        buf.writeBytes([b.3, b.2, b.1, b.0,
                        b.5, b.4, b.7, b.6,
                        b.8, b.9, b.10, b.11,
                        b.12, b.13, b.14, b.15])
    }
}
