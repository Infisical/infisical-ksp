<h1 align="center">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-white.svg#gh-dark-mode-only" alt="infisical">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-black.svg#gh-light-mode-only" alt="infisical">
</h1>

<p align="center">
  <p align="center"><b>Infisical KSP</b>: native Windows code signing with <code>signtool</code>, backed by keys managed in Infisical. Private keys never leave Infisical.</p>
</p>

<h4 align="center">
  <a href="https://infisical.com/docs/documentation/platform/pki/code-signing/overview">Docs</a> |
  <a href="https://infisical.com/slack">Slack</a> |
  <a href="https://infisical.com/">Infisical Cloud</a> |
  <a href="https://www.infisical.com">Website</a>
</h4>

<h4 align="center">
  <a href="https://github.com/Infisical/infisical/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Infisical is released under the MIT license." />
  </a>
  <a href="https://github.com/Infisical/infisical-ksp/issues">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://infisical.com/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
</h4>

## Introduction

The **Infisical KSP** is a Windows [Cryptography API: Next Generation (CNG)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) **Key Storage Provider (KSP)**. It lets the standard Microsoft `signtool` sign `.exe`, `.dll`, and `.msi` artifacts using a code-signing key managed in Infisical Cert Manager. Your tool sends a hash, Infisical signs it, and the signature is embedded in your artifact. **The private key never leaves Infisical.**

It is the Windows-native sibling of the [Infisical PKCS#11 module](https://github.com/Infisical/infisical-pkcs-11): same backend, same sign endpoint, same approvals. PKCS#11 covers cross-platform tools (`jarsigner`, `osslsigncode`, `pkcs11-tool`); this covers native `signtool` on Windows.

Each **Signer** in Infisical Cert Manager appears as one CNG key, selected with signtool's `/kc` flag.

## Features

- **[Remote Signing](https://infisical.com/docs/documentation/platform/pki/code-signing/overview)**: Private keys never leave Infisical. All signing operations are performed by Infisical.
- **Native signtool / Authenticode**: Works with the Microsoft `signtool` you already use, through Windows CNG. No changes to your build pipeline.
- **[RSA and ECDSA Support](#supported-algorithms)**: SHA-256/384/512 with PKCS#1 v1.5 and PSS for RSA, and ECDSA on P-256, P-384, and P-521.
- **[Approval Workflows](#approval-workflow)**: Require human review before signing, bounded by a signature count and/or a time window per approval.
- **Signing activity & audit logs**: Every signing operation is recorded in the Signer's signing activity, and in [Infisical audit logs](https://infisical.com/docs/documentation/platform/audit-logs), with actor, timestamp, and client metadata.
- **Windows x64 and x86**: Pre-built DLLs for the 64-bit and 32-bit `signtool`, registered once per machine.

## Prerequisites

- Access to **Cert Manager** in Infisical
- At least one **Signer** created (Cert Manager > Code Signing > Signers), with a certificate issued from its CA
- A way to authenticate as a member of the Signer with the Administrator or Operator role (the signer's Members tab): either a **Machine Identity** with Universal Auth (have its **Client ID** and **Client Secret** ready) or an Infisical **access token** (a user's or a machine identity's). See [Authentication](#authentication).
- If the Signer has an approval policy: approved signing access before you sign
- A **Windows x64** machine (Windows 10/11 or Windows Server 2016 and later) with Administrator rights (to register the provider)
- **`signtool`** (from the Windows SDK). The provider ships as a 64-bit DLL (`infisical-ksp.dll`) for the 64-bit `signtool` and a 32-bit DLL (`infisical-ksp-x86.dll`) for the 32-bit `signtool`. Use the DLL that matches the `signtool` you run; the 64-bit one is the usual choice.

## Quick Start

### 1. Install

Download the DLL that matches your `signtool` from the [releases page](https://github.com/Infisical/infisical-ksp/releases):

| signtool | File |
|----------|------|
| 64-bit (typical) | `infisical-ksp.dll` |
| 32-bit | `infisical-ksp-x86.dll` |

Or build from source (see [Building from Source](#building-from-source)).

### 2. Register (Administrator, once per machine)

Registering a CNG Key Storage Provider is a few registry entries plus dropping the DLL in
`System32`. Run this from the folder containing `infisical-ksp.dll`, then reboot so CNG loads it:

```powershell
$prov = "Infisical Key Storage Provider"
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography"
Copy-Item .\infisical-ksp.dll "$env:windir\System32\infisical-ksp.dll" -Force
New-Item -Path "$base\Providers\$prov\UM\00010001" -Force | Out-Null
New-ItemProperty -Path "$base\Providers\$prov\UM" -Name Image -PropertyType String -Value "infisical-ksp.dll" -Force | Out-Null
Set-ItemProperty -Path "$base\Providers\$prov\UM\00010001" -Name "(default)" -Value "CRYPT_KEY_STORAGE_INTERFACE"
New-ItemProperty -Path "$base\Providers\$prov\UM\00010001" -Name Flags -PropertyType DWord -Value 0x10000 -Force | Out-Null
New-ItemProperty -Path "$base\Providers\$prov\UM\00010001" -Name Functions -PropertyType MultiString -Value @("KEY_STORAGE") -Force | Out-Null
$iface = "$base\Configuration\Local\Default\00010001\KEY_STORAGE"
$cur = @((Get-ItemProperty $iface).Providers)
if ($cur -notcontains $prov) { Set-ItemProperty -Path $iface -Name Providers -Value ($cur + $prov) }
```

Then reboot once: CNG caches its provider configuration and picks up the new provider on restart.

> **Signing with the 32-bit `signtool`?** It runs under WOW64 and loads providers from `SysWOW64`, so also drop the 32-bit DLL there under the same name. The registry entries above are shared by both architectures, so you do not repeat them:
>
> ```powershell
> Copy-Item .\infisical-ksp-x86.dll "$env:windir\SysWOW64\infisical-ksp.dll" -Force
> ```

### 3. Configure

The provider needs your Infisical server URL and Machine Identity credentials. The simplest setup is environment variables only, with no config file:

```powershell
$env:INFISICAL_SERVER_URL = "https://app.infisical.com"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"
```

`signtool` runs in its own process, so set these in the same session (or CI job) that runs it.

Prefer a config file? Create `%ProgramData%\Infisical\config.json` (or point `INFISICAL_CONFIG` at a custom path) with at least `server_url`, and keep credentials in environment variables:

```json
{
  "server_url": "https://app.infisical.com"
}
```

### 4. Sign

Save the Signer's public certificate to a `.cer` file for signtool's `/f`, then sign. The Signer is selected by name with `/kc`:

```powershell
signtool sign /fd SHA256 /f your-signer.cer `
  /csp "Infisical Key Storage Provider" `
  /kc "your-signer-name" `
  MyApp.exe
```

> **Timestamping:** to keep signatures valid after the certificate expires (recommended for production), add `/tr <rfc3161-timestamp-url> /td SHA256` before the file, pointing `/tr` at an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) Timestamp Authority of your choice.

## Configuration

The provider is configured by environment variables and an optional JSON config file. A config file is not required as long as `server_url` and the credentials are supplied via environment variables. When both are present, environment variables take precedence.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | Machine Identity client ID (Universal Auth) |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | Machine Identity client secret (Universal Auth) |
| `INFISICAL_TOKEN` | An Infisical access token (a user or machine identity JWT). Selects token auth; used instead of Universal Auth credentials |
| `INFISICAL_CONFIG` | Path to config file (default: `%ProgramData%\Infisical\config.json`) |
| `INFISICAL_SERVER_URL` | The Infisical instance URL. Sets `server_url` (and overrides the config file) |

### Config File

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_url` | Yes | (none) | Infisical server URL |
| `auth.method` | No | inferred | Authentication method: `universal-auth` or `token`. Inferred from the credentials when unset (a token means `token`, otherwise `universal-auth`) |
| `auth.client_id` | No | (none) | Machine Identity client ID, for `universal-auth` (prefer env var) |
| `auth.client_secret` | No | (none) | Machine Identity client secret, for `universal-auth` (prefer env var) |
| `auth.token` | No | (none) | Infisical access token, for `token` auth (prefer the env var) |
| `tls.ca_cert_path` | No | (none) | Custom CA certificate for self-hosted instances |
| `tls.skip_verify` | No | `false` | Skip TLS verification (development only) |
| `cache.token_ttl_seconds` | No | `300` | Auth token cache duration |
| `cache.cert_ttl_seconds` | No | `3600` | Certificate data cache duration |
| `cache.signer_ttl_seconds` | No | `300` | Signer list cache duration |
| `approval.signing_duration` | No | — | Auto-request approval with this time window (`"30m"`, `"8h"`, `"2d"`). The provider accepts 1m to 30d as a sanity check; the real limit is the signer's approval policy, which rejects a request asking for longer. The window starts when the request is approved, so time spent waiting for an approver does not eat into it |
| `approval.signing_count` | No | — | Auto-request approval for this many signings |
| `approval.exclude_scope_fields` | No | — | Signing parameters to leave out of the requests the provider opens, so one approval covers any value of them: `command`, `signing_application`, `signing_application_hash`, `hostname`, `os_username`, `ip_address`, `data_hash`. An unknown name is rejected at load |
| `approval.ip_address` | No | — | Pin the requests the provider opens to this address instead of the one Infisical sees them arrive from, which is what it uses when this is unset. It need not be this host's, so you can name a build agent's egress address. Infisical enforces the address it sees either way, so this only ever narrows access |
| `log_level` | No | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `log_file` | No | (disabled) | Path to log file (the provider runs inside signtool, so there is no console) |

<details>
<summary>Full config example</summary>

```json
{
  "server_url": "https://app.infisical.com",
  "auth": {
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  },
  "tls": {
    "ca_cert_path": "C:\\path\\to\\custom-ca.pem",
    "skip_verify": false
  },
  "cache": {
    "token_ttl_seconds": 300,
    "cert_ttl_seconds": 3600,
    "signer_ttl_seconds": 300
  },
  "log_level": "info",
  "log_file": "C:\\ProgramData\\Infisical\\ksp.log"
}
```

</details>

### Authentication

The provider supports two ways to authenticate with Infisical.

**Universal Auth (Machine Identity)** is the default. The provider exchanges the client ID/secret for an access token and refreshes it automatically. Provide the credentials via environment variables (recommended) or the config file:

```powershell
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"
```

**Token auth** uses an Infisical access token directly, either a user's token or a machine identity's. Setting `INFISICAL_TOKEN` selects it:

```powershell
$env:INFISICAL_TOKEN = "your-access-token"
```

> **Token auth is temporary.** The provider uses the token as-is and does not refresh it. When the token expires, signing fails with `401` until you set a new token.

Environment variables take precedence over the config file, and `INFISICAL_TOKEN` takes precedence over Universal Auth credentials.

When credentials are available, the provider authenticates automatically the first time signtool opens it.

## Selecting a Signer

`signtool` selects the key with three flags:

- `/csp` names this provider, the fixed text `"Infisical Key Storage Provider"`.
- `/kc` is the **Signer name** (or ID), the one identifier you choose.
- `/f` is the public certificate file. The provider does not hand certificates to signtool; `/f` supplies the public certificate while the key is selected by `/kc`. Export the Signer's certificate from the Infisical UI (Signer > certificate) and save it as a `.cer`.

## Supported Algorithms

### RSA

| Padding | Hashes | Key sizes |
|---------|--------|-----------|
| PKCS#1 v1.5 | SHA-256, SHA-384, SHA-512 | 2048, 3072, 4096 |
| PSS | SHA-256, SHA-384, SHA-512 | 2048, 3072, 4096 |

### ECDSA

| Hashes | Curves |
|--------|--------|
| SHA-256, SHA-384, SHA-512 | P-256, P-384, P-521 |

## Approval Workflow

If a Signer has an approval policy, you need an approved sign request before signing. Without it, `signtool` fails with an access-denied error and the log file records the `HTTP 403` along with a hint to obtain approved access.

Approvals are granted from the Infisical UI (Cert Manager > Code Signing > Signers > `<signer>` > Approvals tab): request signing access, then have an approver approve it (or an Administrator pre-approve it). Once approved, retrying the same `signtool sign` command succeeds for the granted window.

A request's scope is fixed once it is open. Nobody edits it during review, including the approvers, so a request whose parameters are wrong is rejected and reopened with the ones you want. To have a request cover a series of builds rather than one artifact, leave the parameters that vary out of it in the first place with `approval.exclude_scope_fields`. See [Approvals](https://infisical.com/docs/documentation/platform/pki/code-signing/approvals).

### Automatic approval requests

Add an `approval` block and the provider opens a request for you the first time signing is denied:

```json
{
  "approval": {
    "signing_duration": "8h",
    "signing_count": 10
  }
}
```

That first `signtool sign` still fails, because an approver has to act on the request. The request carries the signing situation the provider observed, so the approval it produces is [scoped](https://infisical.com/docs/documentation/platform/pki/code-signing/approvals#scoping-an-approval) to it:

| Parameter | Captured from |
|-----------|---------------|
| Command | The host process command line (`signtool`, MSBuild, ...). Values following credential flags (`/p`, `-storepass`, `-keypass`, `-pass`, `--password`) are redacted before the command leaves the machine |
| Signing application | The host process executable name, plus its SHA-256 checksum |
| Hostname | The machine the provider runs on |
| OS username | The Windows account running the tool, for example `CORP\buildagent` |
| Data digest | SHA-256 of the payload the denied call submitted. `signtool` submits a digest of the file, so this is not `Get-FileHash yourfile` |

An approver reviews the real command and artifact rather than a blank request. Two things to know before relying on it:

- **The request is pinned to one payload**, so each file needs its own approval and `signing_count` above 1 only allows re-signing that same file. A multi-file `signtool sign` produces one request per file. Add `data_hash` to `approval.exclude_scope_fields` when one approval should cover a batch. A timestamped signature is the common case: the digest changes between runs even for the same file, so pinning it means a fresh approval for every build.
- **The command is compared exactly**, apart from whitespace. Reordering the flags, a different path to the tool, a changed or added argument, writing `/flag value` as `/flag=value`, a per-build temporary path, or a tool upgrade (its checksum changes) all produce a new request.

> **What leaves the machine:** the command line, executable checksum, hostname and Windows account are sent on every sign call and stored on the approval record, where approvers and auditors can read them. Credential flag values are redacted, but review the list above if your commands carry other sensitive arguments.

Every value except the digest is reported by the provider, so it identifies well-behaved tooling rather than defending against a caller talking straight to the API. The digest is recomputed by Infisical from the payload it is asked to sign, which is why it holds regardless. The provider does not observe an IP address, because the address that matters is the one Infisical receives the sign call from, after any NAT or proxy in between. Infisical fills that address in for you, so requests are scoped by address by default. Set `approval.ip_address` to pin a different one, which is how you tie an approval to a build agent's egress address, or add `ip_address` to `approval.exclude_scope_fields` to leave signing unrestricted by address. Infisical always compares against the address it sees, so neither setting can widen access.

> **Note:** retrying a denied command does not pile up duplicates. The server treats a pending request from the same requester as the same ask when its scope, its signature count and the length of its signing window all match, so a retry resumes that request instead of opening another.
>
> This holds for a Machine Identity, which is the intended setup for a build agent. If you configure `INFISICAL_TOKEN` with a **user** token instead, each retry opens its own request, because requests made by a person are matched on the exact window rather than its length.

## Uninstall

To remove the provider, run this in an **Administrator** PowerShell, then **reboot** (Windows keeps the provider in its cached list until a restart):

```powershell
$prov = "Infisical Key Storage Provider"
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography"
Remove-Item "$base\Providers\$prov" -Recurse -Force -ErrorAction SilentlyContinue
$iface = "$base\Configuration\Local\Default\00010001\KEY_STORAGE"
$cur = @((Get-ItemProperty $iface -ErrorAction SilentlyContinue).Providers) | Where-Object { $_ -ne $prov }
Set-ItemProperty -Path $iface -Name Providers -Value $cur
Remove-Item "$env:windir\System32\infisical-ksp.dll" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:windir\SysWOW64\infisical-ksp.dll" -Force -ErrorAction SilentlyContinue
```

This deletes the registry entries and removes the DLL from `System32` (and `SysWOW64` if you installed the 32-bit DLL). Your `%ProgramData%\Infisical` config and log files are left in place; delete that folder too if you no longer need them.

## Troubleshooting

Enable debug logging by adding to your config file:

```json
{
  "log_level": "debug",
  "log_file": "C:\\ProgramData\\Infisical\\ksp.log"
}
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| signtool `Invalid provider specified`, or signing fails right after registering | CNG has not loaded the newly registered provider | Reboot once after registering (CNG caches its provider configuration) |
| signtool access-denied; `HTTP 403` in the log | The identity lacks approved signing access, or is not a Signer member with the Administrator or Operator role | Approve a request (or pre-approve one), or fix the role, then retry the same command |
| `401` in the log | Missing or wrong Machine Identity credentials | Set `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` and `CLIENT_SECRET`; confirm the identity is a Signer member with the Administrator or Operator role (Auditors cannot sign) |
| `auth method temporarily locked` in the log | Too many failed logins (usually wrong credentials) | Wait a few minutes for the lockout to clear, then retry with the correct credentials |
| `No certificates were found that met all the given criteria` | The `/f` certificate does not match the `/kc` Signer | Use the certificate that belongs to the Signer |
| signtool fails immediately and the log you configured stays empty | The config file could not be read, so the log path in it is unknown too | The reason is written to the default log instead. Read `%ProgramData%\Infisical\ksp.log`, which names the setting at fault (an unknown `exclude_scope_fields` entry, a malformed `ip_address`, or invalid JSON such as a UTF-8 BOM) |
| Build cannot find `ncrypt_provider.h` | CPDK not installed, or its `Include` not on `INCLUDE` | Install the CPDK (download id=30688); add its `Include` folder to `INCLUDE` or `CGO_CFLAGS` |

## Building from Source

Clone the repository first:

```bash
git clone https://github.com/Infisical/infisical-ksp.git
cd infisical-ksp
```

The DLL itself is cgo and Windows-only. Build it on Windows (Go 1.24+, a C compiler such as MinGW or MSVC, the Windows SDK, and the Cryptographic Provider Development Kit for `ncrypt_provider.h`):

```powershell
$env:CGO_ENABLED = "1"
go build -buildmode=c-shared -o build\infisical-ksp.dll .\cmd\ksp
```

The OS-agnostic packages (`internal/infisical`, `internal/cng`) build and test on any platform (Linux, macOS, or Windows), which is enough for working on everything except the cgo bridge:

```bash
make test   # go test ./...
make vet    # go vet ./...
```

## Security

- **Private keys never leave Infisical.** All signing happens inside Infisical; only the public certificate is written to the machine.
- **Use environment variables for credentials** to avoid committing secrets to config files.
- If using config-file credentials, restrict permissions on the config file.
- Auth tokens are cached in memory only, never written to disk.
- Enable [approval policies](https://infisical.com/docs/documentation/platform/pki/code-signing/approvals) on signers to require human review before signing.
- Every signing operation is recorded in [Infisical audit logs](https://infisical.com/docs/documentation/platform/audit-logs) with actor, timestamp, and client metadata.

Please do not file GitHub issues or post on public forums for security vulnerabilities. If you believe you have uncovered a vulnerability, contact [security@infisical.com](mailto:security@infisical.com).

## Contributing

Whether it's big or small, we love contributions. Check out our [contributing guide](https://infisical.com/docs/contributing/getting-started) to get started.

Not sure where to get started? Join our [Slack](https://infisical.com/slack) and ask us any questions.
