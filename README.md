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

Each **Signer** in your Infisical project appears as one CNG key, selected with signtool's `/kc` flag.

## Features

- **[Remote Signing](https://infisical.com/docs/documentation/platform/pki/code-signing/overview)**: Private keys never leave Infisical. All signing operations are performed by Infisical.
- **Native signtool / Authenticode**: Works with the Microsoft `signtool` you already use, through Windows CNG. No changes to your build pipeline.
- **[RSA and ECDSA Support](#supported-algorithms)**: SHA-256/384/512 with PKCS#1 v1.5 and PSS for RSA, and ECDSA on P-256, P-384, and P-521.
- **[Approval Workflows](#approval-workflow)**: Require human review before signing, bounded by a signature count and/or a time window per approval.
- **[Audit Logging](https://infisical.com/docs/documentation/platform/audit-logs)**: Every signing operation is recorded with actor, timestamp, and client metadata.
- **Windows x86_64**: A single pre-built DLL, registered once per machine.

## Prerequisites

- An Infisical instance with the **Cert Manager** product enabled
- At least one **Signer** created (Cert Manager > Code Signing > Signers)
- The Signer must be backed by an Internal CA, AWS Private CA, or Azure AD CS
- A **Machine Identity** configured for Universal Auth, added as a member of the Signer with the Administrator or Operator role. Membership is configured on the signer's Members tab.
- If using approval policies: an approved sign request for the signer before signing
- A **Windows x64** machine (Windows 10/11 or Windows Server 2016 and later) with Administrator rights (to register the provider)
- The **64-bit `signtool`** (from the Windows SDK). The provider is 64-bit, so the 32-bit `signtool` cannot load it.

## Quick Start

### 1. Install

Download `infisical-ksp.dll` from the [releases page](https://github.com/Infisical/infisical-ksp/releases):

| Platform | File |
|----------|------|
| Windows x86_64 | `infisical-ksp.dll` |

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

### 3. Configure

Create `%ProgramData%\Infisical\config.json` (or set `INFISICAL_KSP_CONFIG` to a custom path):

```json
{
  "server_url": "https://app.infisical.com"
}
```

Set credentials via environment variables (recommended):

```powershell
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"
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

The provider reads a JSON config file and environment variables. Environment variables take precedence over config file values for credentials.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | Machine Identity client ID |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | Machine Identity client secret |
| `INFISICAL_KSP_CONFIG` | Path to config file (default: `%ProgramData%\Infisical\config.json`) |
| `INFISICAL_KSP_SERVER_URL` | Override `server_url` from the config file |

### Config File

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_url` | Yes | (none) | Infisical server URL |
| `auth.method` | No | `universal-auth` | Authentication method (only `universal-auth` is supported) |
| `auth.client_id` | No | (none) | Machine Identity client ID (prefer env var) |
| `auth.client_secret` | No | (none) | Machine Identity client secret (prefer env var) |
| `tls.ca_cert_path` | No | (none) | Custom CA certificate for self-hosted instances |
| `tls.skip_verify` | No | `false` | Skip TLS verification (development only) |
| `cache.token_ttl_seconds` | No | `300` | Auth token cache duration |
| `cache.cert_ttl_seconds` | No | `3600` | Certificate data cache duration |
| `cache.signer_ttl_seconds` | No | `300` | Signer list cache duration |
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

The provider uses **[Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth)** (Machine Identity) to authenticate with Infisical. Credentials can be provided two ways (in order of precedence):

1. **Environment variables** (recommended for CI/CD and production):
   ```powershell
   $env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
   $env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"
   ```

2. **Config file** (convenient for development):
   ```json
   {
     "auth": {
       "client_id": "your-client-id",
       "client_secret": "your-client-secret"
     }
   }
   ```

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

Approvals are granted out of band: an approver approves a request (or an Administrator pre-approves one) via the Infisical UI (Cert Manager > Code Signing > Signers > `<signer>` > Approvals tab) or the API. Once approved, retrying the same `signtool sign` command succeeds for the granted window.

> **Note:** Unlike the PKCS#11 module, this provider does not auto-create approval requests; request and approve access out of band before signing.

<details>
<summary>Requesting approval via API</summary>

```powershell
# Authenticate
$token = (Invoke-RestMethod -Method Post `
  -Uri "https://app.infisical.com/api/v1/auth/universal-auth/login" `
  -ContentType "application/json" `
  -Body '{"clientId":"...","clientSecret":"..."}').accessToken

# Request access for an 8-hour window, capped at 10 signatures
$start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$end   = (Get-Date).AddHours(8).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Invoke-RestMethod -Method Post `
  -Uri "https://app.infisical.com/api/v1/cert-manager/signers/your-signer-id/requests" `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $token" } `
  -Body (@{
    justification = "CI/CD release build"
    requestedSignings = 10
    requestedWindowStart = $start
    requestedWindowEnd = $end
  } | ConvertTo-Json)
```

An approver must approve the request via the Infisical UI (Cert Manager > Code Signing > Signers > `<signer>` > Approvals tab). Once approved, signing works for the granted window.

</details>

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
```

This deletes the registry entries and removes the DLL from `System32`. Your `%ProgramData%\Infisical` config and log files are left in place; delete that folder too if you no longer need them.

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
| Build cannot find `ncrypt_provider.h` | CPDK not installed, or its `Include` not on `INCLUDE` | Install the CPDK (download id=30688); add its `Include` folder to `INCLUDE` or `CGO_CFLAGS` |

## Building from Source

The DLL is cgo and Windows-only. Build it on Windows (Go 1.24+, a C compiler such as MinGW or MSVC, the Windows SDK, and the Cryptographic Provider Development Kit for `ncrypt_provider.h`):

```powershell
$env:CGO_ENABLED = "1"
go build -buildmode=c-shared -o build\infisical-ksp.dll .\cmd\ksp
```

The OS-agnostic packages build and test on any platform:

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
