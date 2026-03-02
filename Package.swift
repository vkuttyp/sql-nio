// swift-tools-version: 5.9
import PackageDescription

// SQLite is provided by the Apple SDK on Darwin; on Linux we need a system library.
#if canImport(Darwin)
let sqliteSystemLibTargets: [Target] = []
let sqliteNioExtraDeps:       [Target.Dependency] = []
let sqliteNioLinkerSettings:  [LinkerSetting] = [.linkedLibrary("sqlite3")]
#else
// On Linux and Android cross-compilation:
//   CSQLite.h does `#include <sqlite3.h>` (angle brackets → system search path).
//   Linux:   resolves to /usr/include/sqlite3.h  (with libsqlite3-dev)
//   Android: resolves to $(NDK_SYSROOT)/usr/include/sqlite3.h (NDK public API since API 5)
let sqliteSystemLibTargets: [Target] = [
    .target(
        name: "CSQLite",
        publicHeadersPath: "include",
        linkerSettings: [.linkedLibrary("sqlite3")]
    ),
]
let sqliteNioExtraDeps:       [Target.Dependency] = [.target(name: "CSQLite")]
let sqliteNioLinkerSettings:  [LinkerSetting] = []
#endif

let package = Package(
    name: "CosmoSQLClient",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "CosmoSQLCore",    targets: ["CosmoSQLCore"]),
        .library(name: "CosmoMSSQL",      targets: ["CosmoMSSQL"]),
        .library(name: "CosmoPostgres",   targets: ["CosmoPostgres"]),
        .library(name: "CosmoMySQL",      targets: ["CosmoMySQL"]),
        .library(name: "CosmoSQLite",     targets: ["CosmoSQLite"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git",          from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git",      from: "2.25.0"),
        .package(url: "https://github.com/apple/swift-log.git",          from: "1.5.3"),
        .package(url: "https://github.com/apple/swift-crypto.git",       from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin.git",  from: "1.3.0"),
    ],
    targets: [
        // ── Core ─────────────────────────────────────────────────────────────
        .target(
            name: "CosmoSQLCore",
            dependencies: [
                .product(name: "NIOCore",   package: "swift-nio"),
                .product(name: "Logging",   package: "swift-log"),
            ],
            swiftSettings: swiftSettings
        ),

        // ── MSSQL (TDS 7.4) ──────────────────────────────────────────────────
        .target(
            name: "CosmoMSSQL",
            dependencies: [
                .target(name: "CosmoSQLCore"),
                .product(name: "NIOCore",       package: "swift-nio"),
                .product(name: "NIOTLS",        package: "swift-nio"),
                .product(name: "NIOPosix",      package: "swift-nio"),
                .product(name: "NIOSSL",        package: "swift-nio-ssl"),
                .product(name: "Logging",       package: "swift-log"),
                .product(name: "Crypto",        package: "swift-crypto"),
            ],
            swiftSettings: swiftSettings
        ),

        // ── PostgreSQL (wire protocol v3) ────────────────────────────────────
        .target(
            name: "CosmoPostgres",
            dependencies: [
                .target(name: "CosmoSQLCore"),
                .product(name: "NIOCore",       package: "swift-nio"),
                .product(name: "NIOPosix",      package: "swift-nio"),
                .product(name: "NIOSSL",        package: "swift-nio-ssl"),
                .product(name: "Logging",       package: "swift-log"),
                .product(name: "Crypto",        package: "swift-crypto"),
            ],
            swiftSettings: swiftSettings
        ),

        // ── MySQL (wire protocol v10) ─────────────────────────────────────────
        .target(
            name: "CosmoMySQL",
            dependencies: [
                .target(name: "CosmoSQLCore"),
                .product(name: "NIOCore",       package: "swift-nio"),
                .product(name: "NIOPosix",      package: "swift-nio"),
                .product(name: "NIOSSL",        package: "swift-nio-ssl"),
                .product(name: "Logging",       package: "swift-log"),
                .product(name: "Crypto",        package: "swift-crypto"),
            ],
            swiftSettings: swiftSettings
        ),

        // ── SQLite (embedded) ─────────────────────────────────────────────────
        .target(
            name: "CosmoSQLite",
            dependencies: [
                .target(name: "CosmoSQLCore"),
                .product(name: "NIOCore",   package: "swift-nio"),
                .product(name: "NIOPosix",  package: "swift-nio"),
                .product(name: "Logging",   package: "swift-log"),
            ] + sqliteNioExtraDeps,
            swiftSettings: swiftSettings,
            linkerSettings: sqliteNioLinkerSettings
        ),

        // ── Tests ─────────────────────────────────────────────────────────────
        .testTarget(
            name: "CosmoSQLCoreTests",
            dependencies: [
                .target(name: "CosmoSQLCore"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CosmoMSSQLTests",
            dependencies: [
                .target(name: "CosmoMSSQL"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CosmoPostgresTests",
            dependencies: [
                .target(name: "CosmoPostgres"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CosmoMySQLTests",
            dependencies: [
                .target(name: "CosmoMySQL"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CosmoSQLiteTests",
            dependencies: [
                .target(name: "CosmoSQLite"),
            ],
            swiftSettings: swiftSettings
        ),
    ] + sqliteSystemLibTargets
)

var swiftSettings: [SwiftSetting] { [] }
