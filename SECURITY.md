# Security Policy

gmacFTP handles server addresses, usernames, passwords, local paths, and file transfers, so security issues should be treated carefully.

## Supported Versions

The project is pre-1.0. Security fixes are handled on the main development line until formal releases exist.

## Reporting A Vulnerability

If the repository is published with GitHub Security Advisories enabled, report vulnerabilities privately through that feature.

If private advisories are not available yet, open a minimal issue that describes the class of problem without including credentials, server names, logs with tokens, or private file paths. Maintainers can then coordinate a safe disclosure path.

## Sensitive Data Rules

Do not attach:

- Real FTP/SFTP passwords
- Private connection export files
- Full local home-directory screenshots
- Production host lists
- Keychain or vault files
- Logs containing credentials, tokens, or private paths

Use localhost test servers or placeholder domains such as `example.com` when reproducing issues.
