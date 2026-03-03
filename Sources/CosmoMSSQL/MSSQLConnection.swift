@preconcurrency import NIOCore
@preconcurrency import NIOPosix
@preconcurrency import NIOSSL
import Logging
import CosmoSQLCore
import Foundation

// ── MSSQLConnection ───────────────────────────────────────────────────────────
//
// A single async/await connection to a Microsoft SQL Server instance.
// Uses the TDS 7.4 wire protocol over swift-nio.
//
// Usage:
// ```swift
// let config = MSSQLConfiguration(host: "localhost", port: 1433,
//                                  database: "mydb",
//                                  username: "sa", password: "secret")
// let conn = try await MSSQLConnection.connect(configuration: config)
// defer { try? await conn.close() }
//
// let rows = try await conn.query("SELECT id, name FROM users WHERE active = @p1", [.bool(true)])
// for row in rows {
//     print(row["name"].asString() ?? "")
// }
// ```

public final class MSSQLConnection: SQLDatabase, @unchecked Sendable {

    // MARK: - Public configuration

    public struct Configuration: Sendable {
        public var host:           String
        public var port:           Int        = 1433
        public var database:       String
        /// SQL Server username. Not required when using Windows/NTLM authentication (`domain` is set).
        public var username:       String     = ""
        /// SQL Server password. Not required when using Windows/NTLM authentication (`domain` is set).
        public var password:       String     = ""
        public var tls:            SQLTLSConfiguration = .prefer
        /// When `true`, the server's TLS certificate is accepted without verification
        /// (equivalent to `TrustServerCertificate=true` in a SQL Server connection string).
        /// Set this to `true` when connecting to servers with self-signed certificates (e.g. dev/test).
        public var trustServerCertificate: Bool = false
        public var logger:         Logger     = Logger(label: "MSSQLNio")
        /// Timeout for establishing the TCP + TLS + Login7 handshake (seconds). nil = no limit.
        public var connectTimeout: TimeInterval? = 30
        /// Timeout for each individual query (seconds). nil = no limit.
        public var queryTimeout:   TimeInterval? = nil
        /// Set ApplicationIntent=ReadOnly in Login7 (for Availability Group read replicas).
        public var readOnly:       Bool       = false
        /// Windows domain for NTLM/Windows authentication. When set, NTLMv2 is used and
        /// username/password are optional (empty strings use the current process credentials).
        public var domain:         String?    = nil

        /// SQL Server authentication (username + password required).
        public init(host: String, port: Int = 1433,
                    database: String, username: String, password: String,
                    tls: SQLTLSConfiguration = .prefer,
                    trustServerCertificate: Bool = false,
                    connectTimeout: TimeInterval? = 30,
                    queryTimeout:   TimeInterval? = nil,
                    readOnly:       Bool = false) {
            self.host                   = host
            self.port                   = port
            self.database               = database
            self.username               = username
            self.password               = password
            self.tls                    = tls
            self.trustServerCertificate = trustServerCertificate
            self.connectTimeout         = connectTimeout
            self.queryTimeout           = queryTimeout
            self.readOnly               = readOnly
        }

        /// Windows/NTLM authentication. Username and password are optional;
        /// when omitted the NTLM NEGOTIATE is sent without explicit credentials
        /// and the server uses the connecting account's identity.
        public init(host: String, port: Int = 1433,
                    database: String,
                    domain: String,
                    username: String = "",
                    password: String = "",
                    tls: SQLTLSConfiguration = .prefer,
                    trustServerCertificate: Bool = false,
                    connectTimeout: TimeInterval? = 30,
                    queryTimeout:   TimeInterval? = nil,
                    readOnly:       Bool = false) {
            self.host                   = host
            self.port                   = port
            self.database               = database
            self.domain                 = domain
            self.username               = username
            self.password               = password
            self.tls                    = tls
            self.trustServerCertificate = trustServerCertificate
            self.connectTimeout         = connectTimeout
            self.queryTimeout           = queryTimeout
            self.readOnly               = readOnly
        }

        /// Initialise from a SQL Server connection string.
        ///
        /// Supported keys (case-insensitive):
        /// - `Server` / `Data Source`  — host, or `host,port`
        /// - `Database` / `Initial Catalog`
        /// - `User Id` / `UID`
        /// - `Password` / `PWD`
        /// - `Domain`                  — enables NTLM/Windows auth
        /// - `Encrypt`                 — `True` → `.require`, `False` → `.disable`
        /// - `TrustServerCertificate`  — `True` skips certificate verification
        /// - `Connect Timeout`         — seconds (default 30)
        /// - `Application Intent`      — `ReadOnly` sets read-only mode
        ///
        /// Example:
        /// ```
        /// Server=myServer;Database=myDb;User Id=sa;Password=secret;
        /// Encrypt=True;TrustServerCertificate=True;
        /// ```
        public init(connectionString: String) throws {
            // Parse key=value pairs separated by semicolons
            var pairs: [String: String] = [:]
            for part in connectionString.split(separator: ";", omittingEmptySubsequences: true) {
                let kv = part.split(separator: "=", maxSplits: 1)
                guard kv.count == 2 else { continue }
                let key   = kv[0].trimmingCharacters(in: .whitespaces).lowercased()
                let value = kv[1].trimmingCharacters(in: .whitespaces)
                pairs[key] = value
            }

            func get(_ keys: String...) -> String? {
                keys.first(where: { pairs[$0.lowercased()] != nil }).flatMap { pairs[$0.lowercased()] }
            }
            func bool(_ keys: String...) -> Bool {
                get(keys[0], keys.dropFirst().joined())?.lowercased() == "true"
            }

            // Server / Data Source — accepts "host" or "host,port"
            let serverRaw = get("server", "data source") ?? "localhost"
            if serverRaw.contains(",") {
                let parts = serverRaw.split(separator: ",", maxSplits: 1)
                self.host = String(parts[0]).trimmingCharacters(in: .whitespaces)
                self.port = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 1433
            } else {
                self.host = serverRaw
                self.port = 1433
            }

            guard let db = get("database", "initial catalog") else {
                throw SQLError.connectionError("Connection string missing 'Database' / 'Initial Catalog'")
            }
            self.database = db
            self.username = get("user id", "uid") ?? ""
            self.password = get("password", "pwd") ?? ""
            self.domain   = get("domain")

            // Encrypt → tls  (supports: True/False/Disable/Strict/Request/Optional/Mandatory)
            if let enc = get("encrypt") {
                switch enc.lowercased() {
                case "true",  "yes", "mandatory", "require", "strict": self.tls = .require
                case "false", "no",  "optional",  "request":           self.tls = .prefer
                case "disable", "off":                                  self.tls = .disable
                default:                                                self.tls = .prefer
                }
            } else {
                self.tls = .prefer
            }

            self.trustServerCertificate = bool("trustservercertificate")
            self.connectTimeout = get("connect timeout", "connection timeout")
                .flatMap { Double($0) } ?? 30
            self.readOnly = get("applicationintent", "application intent")?
                .lowercased() == "readonly"
        }

        /// Verify the server is reachable at TCP level before attempting a full connection.
        ///
        /// Equivalent to `SQLClient.checkReachability(server:port:)` in SQLClient-Swift.
        /// Use this for a fast fail-early check before calling `MSSQLConnection.connect(configuration:)`.
        ///
        /// - Parameter timeout: Maximum seconds to wait for a TCP connection. Default 5.
        /// - Throws: `SQLError.connectionError` if the host/port is not reachable.
        public func checkReachability(
            timeout: TimeInterval = 5,
            eventLoopGroup: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton
        ) async throws {
            try await MSSQLConnection.checkReachability(
                host: host, port: port, timeout: timeout, eventLoopGroup: eventLoopGroup
            )
        }
    }

    // MARK: - Internal state

    private let channel:       any Channel
    private let logger:        Logger
    let config:                Configuration  // internal — used by backup extension
    private var isClosed:      Bool = false
    /// True when the connection is still open and usable.
    public  var isOpen:        Bool { !isClosed }
    private var msgReader:     TDSFrameReader?  // AsyncThrowingStream-based; no eventLoop hop per read
    /// Tracks whether we are inside an explicit transaction (BEGIN TRANSACTION).
    private var inTransaction: Bool = false
    /// Current transaction descriptor — updated from ENVCHANGE type 8/9/10 responses.
    private var transactionDescriptor: UInt64 = 0
    /// Optional handler called for every INFO/PRINT message received from the server.
    public  var onInfoMessage: ((Int, String) -> Void)? = nil

    // MARK: - Connect

    public static func connect(
        configuration: Configuration,
        eventLoopGroup: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        sslContext: NIOSSLContext? = nil
    ) async throws -> MSSQLConnection {        let channel = try await mssqlWithTimeout(configuration.connectTimeout) {
            // Swift 6: ClientBootstrap is not Sendable; capture host/port as value types instead.
            let host = configuration.host
            let port = configuration.port
            return try await ClientBootstrap(group: eventLoopGroup)
                .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_KEEPALIVE), value: 1)
                .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
                .connect(host: host, port: port).get()
        }

        let conn = MSSQLConnection(channel: channel,
                                   config: configuration,
                                   logger: configuration.logger)
        try await conn.handshake(sslContext: sslContext)
        return conn
    }

    private init(channel: any Channel, config: Configuration, logger: Logger) {
        self.channel = channel
        self.config  = config
        self.logger  = logger
    }

    // MARK: - TDS Handshake (Pre-Login → TLS → Login7)

    private let tlsFramer = TDSTLSFramer()

    private func handshake(sslContext: NIOSSLContext? = nil) async throws {
        // 1. Add pipeline: TDSTLSFramer (pass-through initially) + framing + bridge
        let bridge = TDSFrameBridge()
        // Swift 6: ByteToMessageHandler has Sendable marked unavailable (event-loop-bound).
        let bridgeBox = _UnsafeSendable(bridge)
        let frameBox  = _UnsafeSendable(ByteToMessageHandler(TDSFramingHandler()))
        let framer = tlsFramer
        try await channel.eventLoop.submit {
            try self.channel.pipeline.syncOperations.addHandlers([framer, frameBox.value, bridgeBox.value])
        }.get()
        msgReader = TDSFrameReader(bridge)

        // 2. Pre-Login — negotiate encryption preference
        let preLoginResp = try await sendPreLogin()
        logger.debug("Pre-login: server encryption=\(preLoginResp.encryption)")

        // 3. TDS-TLS upgrade if server requires/offers encryption
        let needTLS: Bool
        switch config.tls {
        case .require: needTLS = true
        case .prefer:  needTLS = preLoginResp.encryption == .on
                                  || preLoginResp.encryption == .required
        case .disable: needTLS = false
        }
        if needTLS {
            try await upgradeTLS(sslContext: sslContext)
            logger.debug("TLS established")
        }

        // 4. Login7
        try await sendLogin7()
        logger.debug("Logged in as \(config.username)")
    }

    // MARK: - Pre-Login

    private func sendPreLogin() async throws -> TDSPreLoginResponse {
        // Request encryption when it's not explicitly disabled; the server decides
        // whether to enforce it.
        let wantEnc: PreLoginEncryption = config.tls == .disable ? .off : .on
        let req = TDSPreLoginRequest(encryption: wantEnc)
        var payload = req.encode(allocator: channel.allocator)
        sendPacket(type: .preLogin, payload: &payload)
        let responseBuffer = try await receivePacket()
        var buf = responseBuffer
        return try TDSPreLoginResponse.decode(from: &buf)
    }

    // MARK: - TDS-TLS upgrade
    //
    // TLS for TDS is NOT standard TLS-on-TCP.  The TLS handshake records are
    // wrapped inside TDS Pre-Login packets (type 0x12).  After the handshake
    // completes, subsequent data (Login7, SQL Batch …) is sent as plain TLS
    // records over TCP — no more TDS wrapping.
    //
    // Pipeline during handshake:
    //   Network ↔ TDSTLSFramer(active) ↔ NIOSSLClientHandler ↔ TDSFramingHandler ↔ Bridge
    //
    // Pipeline after handshake (TDSTLSFramer switches to pass-through):
    //   Network ↔ TDSTLSFramer(pass-through) ↔ NIOSSLClientHandler ↔ TDSFramingHandler ↔ Bridge

    private func upgradeTLS(sslContext sslCtx: NIOSSLContext? = nil) async throws {
        // Use pre-built context from pool, or build one on the fly for direct connections.
        let sslContext: NIOSSLContext
        if let ctx = sslCtx {
            sslContext = ctx
        } else {
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            if config.trustServerCertificate {
                tlsConfig.certificateVerification = .none
            }
            sslContext = try NIOSSLContext(configuration: tlsConfig)
        }
        // IP addresses cannot be used for SNI — pass nil to disable SNI for IP hosts
        let sniHostname: String? = {
            // IPv4: all chars are digits or dots
            if config.host.unicodeScalars.allSatisfy({ $0.value >= 48 && $0.value <= 57 || $0 == "." }) {
                return nil
            }
            // IPv6: contains colon
            if config.host.contains(":") { return nil }
            return config.host
        }()
        let sslHandler = try NIOSSLClientHandler(context: sslContext,
                                                  serverHostname: sniHostname)

        // Promise fulfilled by TLSHandshakeTracker when TLS handshake completes
        let promise = channel.eventLoop.makePromise(of: Void.self)
        let tracker = TLSHandshakeTracker(framer: tlsFramer, promise: promise)

        // Activate TDSTLSFramer so it wraps TLS records in TDS Pre-Login packets
        tlsFramer.active = true

        // Insert NIOSSLClientHandler and tracker between TDSTLSFramer and TDSFramingHandler.
        // Because the channel is already active, NIOSSLClientHandler's handlerAdded()
        // triggers the TLS handshake automatically.
        //
        // Swift 6: NIOSSLHandler explicitly marks Sendable unavailable (it is event-loop-bound).
        // We use syncOperations (no Sendable requirement) from within an event-loop submit block,
        // bridging with an @unchecked Sendable box since we immediately hand ownership to the loop.
        let sslBox = _UnsafeSendable(sslHandler)
        try await channel.eventLoop.submit {
            try self.channel.pipeline.syncOperations.addHandler(
                sslBox.value, position: .after(self.tlsFramer))
            try self.channel.pipeline.syncOperations.addHandler(
                tracker, position: .after(sslBox.value))
        }.get()

        // Wait for TLS handshake to complete (tracker fulfils promise + deactivates framer)
        try await promise.futureResult.get()

        // Remove the one-shot tracker; TDSTLSFramer stays (now in pass-through mode)
        try await channel.pipeline.removeHandler(tracker).get()
    }

    // MARK: - Login7

    private func sendLogin7() async throws {
        let useNTLM = config.domain != nil
        var login = TDSLogin7(
            username:   useNTLM ? "" : config.username,
            password:   useNTLM ? "" : config.password,
            hostname:   ProcessInfo.processInfo.hostName,
            serverName: config.host,
            database:   config.database,
            readOnly:   config.readOnly
        )
        if useNTLM {
            // NTLM step 1: send NTLM_NEGOTIATE in the SSPI field
            login.sspiData = NTLMAuth.buildNegotiate()
            login.optionFlags2 |= 0x80   // fIntSecurity: use integrated (SSPI) auth
        }
        var payload = login.encode(allocator: channel.allocator)
        sendPacket(type: .tdsLogin7, payload: &payload)
        let responseBuffer = try await receivePacket()
        var buf = responseBuffer
        var dec = TDSTokenDecoder()
        try dec.decode(buffer: &buf)

        if useNTLM {
            // NTLM step 2: parse SSPI challenge from server and send NTLM_AUTHENTICATE
            guard let challenge = dec.sspiData else {
                if let error = dec.serverError { throw error }
                throw SQLError.authenticationFailed("NTLM challenge not received from server")
            }
            let domain = config.domain ?? ""
            let authenticate = try NTLMAuth.buildAuthenticate(
                challenge:   challenge,
                username:    config.username,
                password:    config.password,
                domain:      domain,
                workstation: ProcessInfo.processInfo.hostName
            )
            var authBuf = channel.allocator.buffer(capacity: authenticate.count)
            authBuf.writeBytes(authenticate)
            sendPacket(type: .sspiAuth, payload: &authBuf)
            let authResponse = try await receivePacket()
            var authBuf2 = authResponse
            var dec2 = TDSTokenDecoder()
            try dec2.decode(buffer: &authBuf2)
            if let error = dec2.serverError { throw error }
        } else {
            if let error = dec.serverError { throw error }
        }
    }

    // MARK: - SQLDatabase protocol

    /// Execute a query with `@p1, @p2, ...` style or `?` placeholder binds.
    public func query(_ sql: String, _ binds: [SQLValue]) async throws -> [SQLRow] {
        guard !isClosed else { throw SQLError.connectionClosed }
        logger.debug("MSSQL query: \(sql.prefix(120))")
        return try await withTimeout(config.queryTimeout) {
            if binds.isEmpty {
                return try await self.runSQLBatch(sql)
            } else {
                return try await self.runRPC(Self.convertPlaceholders(sql), binds: binds)
            }
        }
    }

    /// Convenience: `?` placeholder variant — identical to `query(_:_:)` but makes intent explicit.
    public func query(_ sql: String, binds: [SQLValue]) async throws -> [SQLRow] {
        try await query(sql, binds)
    }

    // MARK: - Streaming

    /// Stream rows one-by-one as they are decoded from the TDS response.
    ///
    /// Rows are yielded incrementally as TDS packets arrive — without buffering
    /// the entire result set.
    public func queryStream(_ sql: String, _ binds: [SQLValue] = []) -> AsyncThrowingStream<SQLRow, Error> {
        AsyncThrowingStream { cont in
            Task { [self] in
                do {
                    guard !self.isClosed else { throw SQLError.connectionClosed }

                    // Send the query
                    if binds.isEmpty {
                        var payload = encodeSQLBatch(sql: sql)
                        sendPacket(type: .sqlBatch, payload: &payload)
                    } else {
                        let rpc = TDSRPCRequest(sql: Self.convertPlaceholders(sql), binds: binds)
                        var payload = rpc.encode(allocator: channel.allocator)
                        sendPacket(type: .rpc, payload: &payload)
                    }

                    var dec = TDSTokenDecoder()
                    var remainder: ByteBuffer? = nil

                    outerLoop: while true {
                        guard let frame = try await msgReader!.next() else {
                            throw SQLError.connectionClosed
                        }

                        // Append this packet to any leftover bytes from the previous decode
                        if remainder == nil || remainder!.readableBytes == 0 {
                            remainder = frame.payload
                        } else {
                            var combined = channel.allocator.buffer(
                                capacity: remainder!.readableBytes + frame.payload.readableBytes)
                            combined.writeImmutableBuffer(remainder!)
                            combined.writeImmutableBuffer(frame.payload)
                            remainder = combined
                        }

                        // Decode as many complete tokens as possible
                        let rows = dec.decodePartial(buffer: &remainder!)
                        for row in rows { cont.yield(row) }

                        if frame.isEOM { break outerLoop }
                    }

                    if let err = dec.serverError { throw err }
                    if let td = dec.transactionDescriptor { transactionDescriptor = td }
                    dispatchInfoMessages(dec)
                    cont.finish()
                } catch {
                    cont.finish(throwing: error)
                }
            }
        }
    }

    /// Stream individual JSON objects from a `FOR JSON PATH` query.
    ///
    /// SQL Server fragments `FOR JSON PATH` output at ~2033-char row boundaries that do
    /// not align with JSON object boundaries. This method uses ``JSONChunkAssembler`` to
    /// detect exact object boundaries and yields each `Data` value the moment its closing
    /// `}` arrives — without ever buffering the full JSON array.
    ///
    /// Example:
    /// ```swift
    /// for try await data in conn.queryJsonStream(
    ///     "SELECT Id, Name FROM Products FOR JSON PATH") {
    ///     let product = try JSONDecoder().decode(Product.self, from: data)
    /// }
    /// ```
    public func queryJsonStream(_ sql: String, _ binds: [SQLValue] = []) -> AsyncThrowingStream<Data, Error> {
        AsyncThrowingStream { cont in
            Task { [self] in
                do {
                    guard !self.isClosed else { throw SQLError.connectionClosed }
                    let dec: TDSTokenDecoder
                    if binds.isEmpty {
                        dec = try await self.runBatchDecoder(sql)
                    } else {
                        dec = try await self.runRPCDecoder(Self.convertPlaceholders(sql), binds: binds)
                    }
                    var assembler = JSONChunkAssembler()
                    for row in dec.rows {
                        if let text = row.values.first?.asString() {
                            for jsonData in assembler.feed(text) {
                                cont.yield(jsonData)
                            }
                        }
                    }
                    cont.finish()
                } catch {
                    cont.finish(throwing: error)
                }
            }
        }
    }

    /// Stream decoded `Decodable` objects from a `FOR JSON PATH` query.
    public func queryJsonStream<T: Decodable & Sendable>(
        _ type: T.Type, _ sql: String, _ binds: [SQLValue] = []
    ) -> AsyncThrowingStream<T, Error> {
        AsyncThrowingStream { cont in
            Task { [self] in
                do {
                    let decoder = JSONDecoder()
                    for try await data in self.queryJsonStream(sql, binds) {
                        let obj = try decoder.decode(T.self, from: data)
                        cont.yield(obj)
                    }
                    cont.finish()
                } catch {
                    cont.finish(throwing: error)
                }
            }
        }
    }

    public func execute(_ sql: String, _ binds: [SQLValue]) async throws -> Int {
        guard !isClosed else { throw SQLError.connectionClosed }
        logger.debug("MSSQL execute: \(sql.prefix(120))")
        return try await withTimeout(config.queryTimeout) {
            if binds.isEmpty {
                return try await self.runExecuteBatch(sql)
            } else {
                return try await self.runRPCExecute(Self.convertPlaceholders(sql), binds: binds)
            }
        }
    }

    /// Convenience: `?` placeholder variant — identical to `execute(_:_:)` but makes intent explicit.
    public func execute(_ sql: String, binds: [SQLValue]) async throws -> Int {
        try await execute(sql, binds)
    }

    /// Replace `?` positional placeholders with `@p1`, `@p2`, ... (SQL Server sp_executesql style).
    /// If the SQL already uses `@p` style, it is returned unchanged.
    static func convertPlaceholders(_ sql: String) -> String {
        guard sql.contains("?") else { return sql }
        var result = ""
        var index  = 1
        for ch in sql {
            if ch == "?" {
                result += "@p\(index)"
                index  += 1
            } else {
                result.append(ch)
            }
        }
        return result
    }

    // MARK: - Multi-result set query

    /// Execute a query and return **all** result sets (e.g. from a stored procedure
    /// that contains multiple SELECT statements).
    public func queryMulti(_ sql: String, _ binds: [SQLValue] = []) async throws -> [[SQLRow]] {
        guard !isClosed else { throw SQLError.connectionClosed }
        logger.debug("MSSQL queryMulti: \(sql.prefix(120))")
        return try await withTimeout(config.queryTimeout) {
            let dec: TDSTokenDecoder
            if binds.isEmpty {
                dec = try await self.runBatchDecoder(sql)
            } else {
                dec = try await self.runRPCDecoder(sql, binds: binds)
            }
            self.dispatchInfoMessages(dec)
            return dec.resultSets
        }
    }

    // MARK: - Stored procedure call

    /// Call a named stored procedure, capturing all result sets, OUTPUT parameters,
    /// and the `RETURN` status.
    public func callProcedure(_ name: String, parameters: [SQLParameter] = []) async throws -> MSSQLProcResult {
        guard !isClosed else { throw SQLError.connectionClosed }
        logger.debug("MSSQL callProcedure: \(name)")
        return try await withTimeout(config.queryTimeout) {
            let rpc = TDSRPCProcRequest(procName: name, parameters: parameters)
            var payload = rpc.encode(allocator: self.channel.allocator)
            self.sendPacket(type: .rpc, payload: &payload)
            var buf = try await self.receivePacket()
            var dec = TDSTokenDecoder()
            try dec.decode(buffer: &buf)
            if let err = dec.serverError { throw err }
            self.dispatchInfoMessages(dec)
            return MSSQLProcResult(
                resultSets:        dec.resultSets,
                outputParameters:  dec.outputParameters,
                returnStatus:      dec.returnStatus,
                rowsAffected:      dec.rowsAffected,
                infoMessages:      dec.infoMessages)
        }
    }

    // MARK: - Transaction API

    /// Begin an explicit transaction.
    public func beginTransaction() async throws {
        _ = try await runExecuteBatch("BEGIN TRANSACTION")
        inTransaction = true
    }

    /// Commit the current transaction.
    public func commitTransaction() async throws {
        _ = try await runExecuteBatch("COMMIT TRANSACTION")
        inTransaction = false
    }

    /// Roll back the current transaction.
    public func rollbackTransaction() async throws {
        _ = try await runExecuteBatch("ROLLBACK TRANSACTION")
        inTransaction = false
    }

    /// Execute `work` inside a transaction, committing on success or rolling back on error.
    @discardableResult
    public func withTransaction<T: Sendable>(
        _ work: @Sendable (MSSQLConnection) async throws -> T
    ) async throws -> T {
        try await beginTransaction()
        do {
            let result = try await work(self)
            try await commitTransaction()
            return result
        } catch {
            try? await rollbackTransaction()
            throw error
        }
    }

    public func close() async throws {
        guard !isClosed else { return }
        isClosed = true
        try await channel.close().get()
    }

    // MARK: - Reachability

    /// Performs a TCP-level connection attempt to verify the server is reachable
    /// before spending time on TLS handshake and Login7 negotiation.
    ///
    /// Throws `SQLError.connectionError` if the host/port is unreachable within `timeout`.
    public static func checkReachability(
        host: String,
        port: Int = 1433,
        timeout: TimeInterval = 5,
        eventLoopGroup: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton
    ) async throws {
        try await mssqlWithTimeout(timeout) {
            let channel = try await ClientBootstrap(group: eventLoopGroup)
                .connect(host: host, port: port)
                .get()
            try? await channel.close().get()
        }
    }



    /// Run a SQL batch and return the full decoder state (for callers needing resultSets).
    private func runBatchDecoder(_ sql: String) async throws -> TDSTokenDecoder {
        var payload = encodeSQLBatch(sql: sql)
        sendPacket(type: .sqlBatch, payload: &payload)
        var buf = try await receivePacket()
        var dec = TDSTokenDecoder()
        try dec.decode(buffer: &buf)
        if let err = dec.serverError { throw err }
        // Update transaction descriptor if the server sent an ENVCHANGE
        if let td = dec.transactionDescriptor { transactionDescriptor = td }
        return dec
    }

    /// Run an RPC (sp_executesql) and return the full decoder state.
    private func runRPCDecoder(_ sql: String, binds: [SQLValue]) async throws -> TDSTokenDecoder {
        let rpc = TDSRPCRequest(sql: sql, binds: binds)
        var payload = rpc.encode(allocator: channel.allocator)
        sendPacket(type: .rpc, payload: &payload)
        var buf = try await receivePacket()
        var dec = TDSTokenDecoder()
        try dec.decode(buffer: &buf)
        if let err = dec.serverError { throw err }
        return dec
    }

    /// Execute a SQL batch and return rows.
    private func runSQLBatch(_ sql: String) async throws -> [SQLRow] {
        let dec = try await runBatchDecoder(sql)
        dispatchInfoMessages(dec)
        return dec.rows
    }

    /// Execute a SQL batch and return rows-affected count.
    private func runExecuteBatch(_ sql: String) async throws -> Int {
        let dec = try await runBatchDecoder(sql)
        dispatchInfoMessages(dec)
        return dec.rowsAffected
    }

    /// Execute via TDS RPC (sp_executesql) with typed parameters.
    private func runRPC(_ sql: String, binds: [SQLValue]) async throws -> [SQLRow] {
        let dec = try await runRPCDecoder(sql, binds: binds)
        dispatchInfoMessages(dec)
        return dec.rows
    }

    private func runRPCExecute(_ sql: String, binds: [SQLValue]) async throws -> Int {
        let dec = try await runRPCDecoder(sql, binds: binds)
        dispatchInfoMessages(dec)
        return dec.rowsAffected
    }

    private func dispatchInfoMessages(_ dec: TDSTokenDecoder) {
        guard let handler = onInfoMessage else { return }
        for msg in dec.infoMessages { handler(msg.code, msg.message) }
    }

    // MARK: - Timeout helper

    /// Run `work` and throw ``SQLError/timeout`` if it doesn't finish within `seconds`.
    private func withTimeout<T: Sendable>(_ seconds: TimeInterval?, _ work: @Sendable @escaping () async throws -> T) async throws -> T {
        try await mssqlWithTimeout(seconds, work)
    }

    private func sendPacket(type: TDSPacketType, payload: inout ByteBuffer) {
        // Coalesce all TDS packets into a single ByteBuffer and flush in one syscall.
        let payloadSize = payload.readableBytes
        let maxBody = 32768 - TDSPacketHeader.size  // 32760

        // Pre-compute total wire size so we allocate exactly once.
        let fullPackets = payloadSize / maxBody
        let remainder  = payloadSize % maxBody
        let numPackets = fullPackets + (remainder > 0 ? 1 : 0)
        let wireSize   = payloadSize + numPackets * TDSPacketHeader.size
        var wire = channel.allocator.buffer(capacity: wireSize)

        var offset = 0
        var packetID: UInt8 = 1
        while offset < payloadSize {
            let chunkLen = min(maxBody, payloadSize - offset)
            let isLast   = (offset + chunkLen) >= payloadSize
            let totalLen = UInt16(chunkLen + TDSPacketHeader.size)

            let header = TDSPacketHeader(
                type: type,
                status: isLast ? .eom : .normal,
                length: totalLen,
                packetID: packetID
            )
            header.encode(into: &wire)
            wire.writeImmutableBuffer(payload.getSlice(at: payload.readerIndex + offset, length: chunkLen)!)

            packetID = packetID == 255 ? 1 : packetID + 1
            offset += chunkLen
        }
        // Single writeAndFlush → one TCP segment for all packets.
        channel.writeAndFlush(wire, promise: nil)
    }

    /// Receive one complete TDS message via the async stream bridge handler.
    private func receivePacket() async throws -> ByteBuffer {
        guard let reader = msgReader else { throw SQLError.connectionClosed }
        return try await reader.receiveMessage()
    }

    // MARK: - SQL Batch encoding

    private func encodeSQLBatch(sql: String) -> ByteBuffer {
        // ALL_HEADERS: 4-byte total header len + 4-byte header len + 2-byte type(0x0002=TransactionDescriptor)
        // Simplest: send just the UTF-16LE SQL with the mandatory ALL_HEADERS block
        let allHeadersLen: UInt32 = 22   // per TDS spec for SQL Batch with no transaction
        var buf = channel.allocator.buffer(capacity: Int(allHeadersLen) + sql.utf16.count * 2)
        // ALL_HEADERS
        buf.writeInteger(allHeadersLen, endianness: .little)
        buf.writeInteger(UInt32(18), endianness: .little)           // individual header length
        buf.writeInteger(UInt16(2),  endianness: .little)           // type = TRANSACTION_DESCRIPTOR
        buf.writeInteger(transactionDescriptor, endianness: .little) // current transaction (0 = none)
        buf.writeInteger(UInt32(1),  endianness: .little)           // outstanding request count
        // SQL (UTF-16LE)
        for unit in sql.utf16 {
            buf.writeInteger(unit, endianness: .little)
        }
        return buf
    }
}

// MARK: - Package-internal timeout helper (also used by connect static method)

/// Race `work` against a sleep; throw ``SQLError/timeout`` if sleep wins.
func mssqlWithTimeout<T: Sendable>(_ seconds: TimeInterval?, _ work: @Sendable @escaping () async throws -> T) async throws -> T {
    guard let seconds = seconds, seconds > 0 else { return try await work() }
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await work() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw SQLError.timeout
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}
