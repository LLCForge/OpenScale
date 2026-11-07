# Security policy

OpenScale is a single-owner, cloud-free and telemetry-free WireGuard mesh VPN. Vulnerability reports are welcome.

## Supported versions

Only the latest release receives security fixes. Fixes ship as a new release signed with the owner's release key.

## Reporting a vulnerability

- **Do not open a public issue, discussion or pull request for a vulnerability.**
- Use GitHub's private reporting (**Security → Report a vulnerability**) on this repository.
- Include: the affected version and platform, the type and impact of the issue (for example an authentication bypass, a key leak, a kill-switch bypass), steps to reproduce or a proof of concept, and a suggested fix if you have one.
- Never include real keys, network documents or traffic of real people; use a test network.

Reports are confirmed, assessed and fixed as quickly as possible. The project is maintained by a small team, so no fixed response time is promised; a coordinated disclosure date is agreed with the reporter, who is credited in the release notes on request.

## Scope

In scope: the trust core (root key, signed network document, enrollment and revocation), the control protocol and coordinator, the data plane and packet filter, exit nodes and kill switch, the panel and local API, the desktop services, installers and release signing.

Out of scope: attacks that require the owner's root key or administrator rights on the owner's own machine, denial of service by an attacker who controls the network path, and issues in third-party software that OpenScale only interoperates with.
