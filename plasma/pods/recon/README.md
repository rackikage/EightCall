# plasma/pods/hunt — recon evidence for owned targets

Saved `nmap` output (`.nmap`/`.gnmap`/`.xml`) for the enrolled iOS targets
(`iphone01`, `iphone02`, `ipad01`). These are records of scans run against
devices the operator owns, kept for attribution and diffing over time — not a
target list to point tooling at.

Before committing new scan output, confirm it carries no credentials, tokens,
or bystander hosts. Evidence stays on the wire; secrets never land in git.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`); scans target owned devices on networks you
control. No evasion — scans are attributable and recorded. No arbitrary
execution. No secrets in git.
