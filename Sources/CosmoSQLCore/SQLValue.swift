import Foundation

/// A single value that can be bound to a SQL query or read from a result row.
public enum SQLValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case int8(Int8)
    case int16(Int16)
    case int32(Int32)
    case int64(Int64)
    case float(Float)
    case double(Double)
    /// Exact decimal value — used for DECIMAL, NUMERIC, MONEY, SMALLMONEY columns.
    case decimal(Decimal)
    case string(String)
    case bytes([UInt8])
    case uuid(UUID)
    case date(Date)
}

// MARK: - Typed accessors

public extension SQLValue {
    var isNull: Bool { if case .null = self { return true }; return false }

    func asBool()    -> Bool?    { guard case .bool(let v)    = self else { return nil }; return v }
    func asInt() -> Int? {
        switch self {
        case .int(let v):   return v
        case .int8(let v):  return Int(v)
        case .int16(let v): return Int(v)
        case .int32(let v): return Int(v)
        case .int64(let v): return Int(exactly: v)
        default:            return nil
        }
    }
    func asInt32()   -> Int32?   { guard case .int32(let v)    = self else { return nil }; return v }
    func asInt64() -> Int64? {
        switch self {
        case .int64(let v): return v
        case .int32(let v): return Int64(v)
        case .int16(let v): return Int64(v)
        case .int8(let v):  return Int64(v)
        case .int(let v):   return Int64(v)
        default:            return nil
        }
    }
    func asFloat()   -> Float?   { guard case .float(let v)    = self else { return nil }; return v }
    func asDouble()  -> Double?  { guard case .double(let v)   = self else { return nil }; return v }
    func asDecimal() -> Decimal? { guard case .decimal(let v)  = self else { return nil }; return v }
    func asString()  -> String?  { guard case .string(let v)   = self else { return nil }; return v }
    func asBytes()   -> [UInt8]? { guard case .bytes(let v)    = self else { return nil }; return v }
    func asUUID()    -> UUID?    { guard case .uuid(let v)     = self else { return nil }; return v }
    func asDate()    -> Date?    { guard case .date(let v)     = self else { return nil }; return v }

    // Widening unsigned accessors — convert any signed integer case to UInt if value fits.
    func asUInt8() -> UInt8? {
        switch self {
        case .int(let v)   where v >= 0 && v <= 255: return UInt8(v)
        case .int8(let v)  where v >= 0:             return UInt8(v)
        case .int16(let v) where v >= 0 && v <= 255: return UInt8(v)
        case .int32(let v) where v >= 0 && v <= 255: return UInt8(v)
        case .int64(let v) where v >= 0 && v <= 255: return UInt8(v)
        default: return nil
        }
    }
    func asUInt16() -> UInt16? {
        switch self {
        case .int(let v)   where v >= 0 && v <= 65535: return UInt16(v)
        case .int8(let v)  where v >= 0:               return UInt16(v)
        case .int16(let v) where v >= 0:               return UInt16(v)
        case .int32(let v) where v >= 0 && v <= 65535: return UInt16(v)
        case .int64(let v) where v >= 0 && v <= 65535: return UInt16(v)
        default: return nil
        }
    }
    func asUInt32() -> UInt32? {
        switch self {
        case .int(let v)   where v >= 0:               return UInt32(v)
        case .int8(let v)  where v >= 0:               return UInt32(v)
        case .int16(let v) where v >= 0:               return UInt32(v)
        case .int32(let v) where v >= 0:               return UInt32(bitPattern: v)
        case .int64(let v) where v >= 0 && v <= UInt32.max: return UInt32(v)
        default: return nil
        }
    }
    func asUInt64() -> UInt64? {
        switch self {
        case .int(let v)   where v >= 0: return UInt64(v)
        case .int8(let v)  where v >= 0: return UInt64(v)
        case .int16(let v) where v >= 0: return UInt64(v)
        case .int32(let v) where v >= 0: return UInt64(v)
        case .int64(let v) where v >= 0: return UInt64(bitPattern: v)
        default: return nil
        }
    }

    /// Returns the underlying Swift value as `Any`, or `nil` for `.null`.
    ///
    /// Useful for JSON serialization, generic containers, and any code that needs
    /// the unwrapped value without pattern-matching on each `SQLValue` case.
    func toAny() -> Any? {
        switch self {
        case .null:           return nil
        case .bool(let v):    return v
        case .int(let v):     return v
        case .int8(let v):    return v
        case .int16(let v):   return v
        case .int32(let v):   return v
        case .int64(let v):   return v
        case .float(let v):   return v
        case .double(let v):  return v
        case .decimal(let v): return v
        case .string(let v):  return v
        case .bytes(let v):   return v
        case .uuid(let v):    return v
        case .date(let v):    return v
        }
    }
}

// MARK: - ExpressibleBy literals

extension SQLValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}
extension SQLValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) { self = .int(value) }
}
extension SQLValue: ExpressibleByFloatLiteral {
    public init(floatLiteral value: Double) { self = .double(value) }
}
extension SQLValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}
extension SQLValue: ExpressibleByNilLiteral {
    public init(nilLiteral: ()) { self = .null }
}
