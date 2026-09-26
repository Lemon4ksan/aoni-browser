<div align="center">

# aoni-browser

### The Stealth Shield & Evasion Extension for aoni

_«Mimic reality down to the packet margin — where deception becomes mathematical precision»_

[![Go Version](https://img.shields.io/badge/go-1.27%2B-007d9c?logo=go&logoColor=white&style=flat-square)](https://go.dev/)
[![Go Reference](https://img.shields.io/badge/godoc-reference-007d9c?style=flat-square)](https://pkg.go.dev/github.com/lemon4ksan/aoni-browser)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![uTLS Emulation](https://img.shields.io/badge/tls-uTLS%20Presets%20%26%20GREASE-blueviolet?style=flat-square)](option)
[![RFC 9484 ECH](https://img.shields.io/badge/security-RFC%209484%20ECH-success?style=flat-square)](fingerprint/ech)
[![RFC 8879 Compression](https://img.shields.io/badge/compression-RFC%208879%20Cert-orange?style=flat-square)](fingerprint)
[![RFC 7469 Pinning](https://img.shields.io/badge/pinning-RFC%207469%20SPKI-yellow?style=flat-square)](profile)
[![FoxIO JA4](https://img.shields.io/badge/telemetry-FoxIO%20JA4-brightgreen?style=flat-square)](fingerprint/ja4)
[![p0f L4 Spoofing](https://img.shields.io/badge/l4%20stealth-p0f%20SYN%20Spoofing-critical?style=flat-square)](fingerprint/p0f)

**aoni-browser** is the production-grade stealth, fingerprint emulation, and anti-bot resolution engine for [aoni](https://github.com/lemon4ksan/aoni). It enables true browser-grade network fidelity across the entire protocol stack (L4 TCP/IP, L7 TLS/uTLS, HTTP/2 framing, HTTP/3 QUIC transport limits, Client Hints, and cookie partitioning) without modifying or compromising the frozen, zero-allocation core of `aoni`.

#### English • [Architecture Specification](docs/VOODOO.md) • [JA4 Specification](fingerprint/ja4/README.md) • [License](LICENSE)

</div>

## Capabilities & Layer Invariants

| Layer | Evasion & Emulation Vectors | Standard / RFC |
| :--- | :--- | :--- |
| **L4 TCP/IP** | TCP/IP SYN spoofing (`TTL`, `Window Size`, `MSS`, `WScale`, `ECN`, `SACK`), micro-jitter packet padding. | Passive OS Detection (p0f v3) |
| **L7 TLS** | Full uTLS presets (`Chrome 120+`, `Firefox 120+`, `Safari 17+`), dynamic `ClientHello` spec providers. | RFC 8446 (TLS 1.3), GREASE (RFC 8701) |
| **L7 Security** | Encrypted Client Hello (`ECHConfigList`, Base64 configs, auto DNS HTTPS/SVCB discovery). | RFC 9484 / draft-ietf-tls-esni |
| **L7 Resumption**| TLS 1.3 Early Data (`0-RTT`) with LRU session ticket resumption cache. | RFC 8446 / RFC 9001 / RFC 9846 |
| **L7 Certificates**| Dynamic TLS Certificate Compression (Brotli & Zstandard) to shrink flight size. | RFC 8879 |
| **L7 Pinning** | SHA-256 Subject Public Key Info (`SPKI`) pinning with wildcard domain matching (`*.domain.com`). | RFC 7469 §2.4 |
| **L7 HTTP/2** | Browser-accurate `SETTINGS` frames, window update streams, strict `:method, :authority, :scheme, :path` ordering. | RFC 9113 (HTTP/2) |
| **L7 HTTP/3** | QUIC transport limits, stream concurrency bounds, pseudo-header order synchronization. | RFC 9114 (HTTP/3) |
| **Identity** | Automatic `Sec-CH-UA`, `Sec-CH-UA-Platform`, and `Accept-*` headers tied to OS/browser pairs. | W3C Client Hints |
| **State** | Independent proxy-isolated cookie jars with Cookies Having Independent Partitioned State. | CHIPS / draft-cutler-httpbis-partitioned-cookies |
| **Anti-Bot** | Automated Turnstile, JavaScript challenges, and Privacy Pass blind signature resolution. | RFC 9260 / RFC 9576 (VOPRF) |

## Installation

```bash
go get github.com/lemon4ksan/aoni-browser
go get github.com/lemon4ksan/aoni
```

## Quickstart

### 1. Zero-Config Chrome Stealth Profile

With a single option, `aoni-browser` synchronizes every layer of the network stack to Google Chrome running on Windows:

```go
package main

import (
	"context"
	"fmt"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni-browser/option"
)

func main() {
	// Initialize aoni client with full Chrome 120+ desktop profile
	client := aoni.NewClient(nil,
		option.WithChrome(),
	)

	// Outbound request executes with:
	// - Chrome uTLS ClientHello with GREASE extensions
	// - RFC 8879 certificate compression (Brotli/Zstd)
	// - Chrome HTTP/2 SETTINGS frames and stream priorities
	// - Synchronized Sec-CH-UA client hints
	// - CHIPS proxy-isolated cookie jar
	resp, err := client.GetTo[string](context.Background(), "https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Data)
}
```

## Advanced Usage

### 2. Encrypted Client Hello (RFC 9484 ECH)

Encrypt the Server Name Indication (SNI) to defeat SNI-based filtering and ISP censorship:

```go
// Option A: Automatic ECH discovery via DNS HTTPS / SVCB records
client := aoni.NewClient(nil,
	option.WithChrome(),
	option.WithAutoECH(true),
)

// Option B: Explicit Base64-encoded ECHConfigList
echBase64 := "AEb+DQBECAAgAC3z...=="
client := aoni.NewClient(nil,
	option.WithChrome(),
	option.WithECHConfigBase64(echBase64),
)
```

### 3. Subject Public Key Info (SPKI) Pinning (RFC 7469 §2.4)

Enforce strict public key pinning to prevent Man-in-the-Middle (MITM) proxy interception:

```go
client := aoni.NewClient(nil,
	option.WithChrome(),
	// Pin SHA-256 base64 SPKI hash for target domain (supports wildcards)
	option.WithSPKIPin("api.secure-vault.com", "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="),
	option.WithSPKIPin("*.secure-vault.com", "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="),
)
```

### 4. 0-RTT Session Resumption & LRU Session Cache

Accelerate repeat connections to zero round-trips using TLS 1.3 Early Data:

```go
client := aoni.NewClient(nil,
	option.WithChrome(),
	option.With0RTT(true), // Activates TLS 1.3 Early Data resumption
)
```

### 5. Outbound FoxIO JA4 Telemetry & Observability

Capture live JA4 fingerprints calculated during actual handshakes for audit and verification:

```go
client := aoni.NewClient(nil,
	option.WithChrome(),
	option.WithJA4Callback(func(report ja4.Report) {
		fmt.Printf("Outbound TLS JA4: %s\n", report.JA4)
		fmt.Printf("Raw Cipher Count: %d, Extensions: %d\n", report.CipherCount, len(report.Extensions))
	}),
)
```

### 6. Passive OS Fingerprint Spoofing (p0f v3 Evasion)

Spoof kernel-level TCP/IP SYN parameters to match the target operating system stack:

```go
import (
	"github.com/lemon4ksan/aoni-browser/fingerprint/p0f"
	"github.com/lemon4ksan/aoni-browser/option"
)

client := aoni.NewClient(nil,
	option.WithChrome(),
	// Spoof TCP SYN signature: TTL=128, Window=64240, MSS=1460, WScale=8
	option.WithP0fSignature(p0f.Windows10_11_TCP),
)
```

### 7. WAF & Challenge Resolution Pipeline (Privacy Pass & Turnstile)

Integrate automated challenge detection and VOPRF Privacy Pass blind token authorization:

```go
import (
	"github.com/lemon4ksan/aoni-browser/option"
	"github.com/lemon4ksan/aoni-browser/privacypass"
	"github.com/lemon4ksan/aoni-browser/resiliency/challenge"
)

client := aoni.NewClient(nil,
	option.WithChrome(),
	// Automated Cloudflare / Turnstile detection
	option.WithChallengeDetector(challenge.DetectCloudflareChallenge),
	// Privacy Pass (RFC 9260 / RFC 9576) blind token redemption
	option.WithPrivacyPass(privacypass.NewInMemoryProvider()),
)
```

## Option Reference

All options are available under `github.com/lemon4ksan/aoni-browser/option`:

| Function | Description |
| :--- | :--- |
| `WithChrome()` | Complete zero-config Google Chrome Windows desktop profile. |
| `WithChromeMobile()` | Google Chrome mobile profile configured for Android. |
| `WithFirefox()` | Mozilla Firefox desktop profile configured for Windows. |
| `WithSafari()` | Apple Safari desktop profile configured for macOS. |
| `WithBrowserProfile(id, os)` | Selects a browser identity tuned for the specified OS key. |
| `WithProfileVariant(variant, os)` | Applies custom TLS, HTTP/2 SETTINGS, and header rules. |
| `WithTLSFingerprint(fp)` | Maps raw fingerprint specification to uTLS `ClientHello`. |
| `WithTLSClientHelloID(id)` | Sets explicit uTLS `ClientHelloID` preset (e.g. `utls.HelloChrome_120`). |
| `WithTLSClientHelloSpecProvider(p)` | Injects dynamic runtime `ClientHelloSpec` generator. |
| `With0RTT(enable)` | Enables or disables TLS 1.3 Early Data (0-RTT) resumption. |
| `WithSessionCache(cache)` | Injects custom `utls.ClientSessionCache` instance. |
| `WithCertCompression(algos...)` | Enables RFC 8879 certificate compression (Brotli, Zstd). |
| `WithCertificatePin(domain, hash)` | Registers domain SHA-256 SPKI fingerprint pin (RFC 7469). |
| `WithCertificatePins(map)` | Registers batch map of domain SPKI pins. |
| `WithSPKIPin(domain, pin)` | Alias for `WithCertificatePin`. |
| `WithPinnedSPKI(domain, pins...)` | Registers multiple SPKI hashes for a single domain. |
| `WithECHConfig(rawBytes)` | Configures raw RFC 9484 TLS 1.3 Encrypted Client Hello bytes. |
| `WithECHConfigBase64(base64)` | Parses and sets base64-encoded `ECHConfigList`. |
| `WithAutoECH(enable)` | Enables automated ECH discovery via DNS HTTPS / SVCB records. |
| `WithPacketPadding(config)` | Injects random or aligned packet padding into TLS payload writes. |
| `WithJA4Callback(fn)` | Registers real-time FoxIO JA4 fingerprint telemetry callback. |
| `WithP0fSignature(sig)` | Spoofs TCP/IP SYN parameters (TTL, MSS, WinSize, WScale, ECN). |
| `WithPersona(p)` | Applies bundled multi-layer persona identity. |
| `WithPersonaStruct(persona)` | Applies detailed structured persona configuration. |
| `WithPrivacyPass(provider)` | Integrates RFC 9260 / RFC 9576 VOPRF blind token provider. |
| `WithChallengeDetector(fn)` | Registers custom WAF / bot challenge detector function. |
| `WithChallengeSolver(solver)` | Injects automated WAF challenge solver pipeline. |

## Architecture (Inversion of Control)

```
       +-------------------------------------------------------------+
       |                        User Code                            |
       |  client := aoni.NewClient(nil, option.WithChrome())         |
       +------------------------------+------------------------------+
                                      |
       +------------------------------v------------------------------+
       |                 aoni-browser (Stealth Orchestrator)         |
       |  - profile.EnsureWrapTLSClient(cfg)                         |
       |  - profile.ApplyHTTPVariantToConfig(cfg)                    |
       |  - profile.ApplyProfileHeaders(req)                         |
       +------------------------------+------------------------------+
                                      | Config Hooks (ExtensionConfig)
       +------------------------------v------------------------------+
       |                  aoni (High-Performance Engine)             |
       |  - WrapTLSClient hook -> executes HandshakeUTLS            |
       |  - OverrideH2Settings -> browser SETTINGS frames            |
       |  - HeaderOrder        -> strict pseudo-header serialization |
       |  - UniversalDialer    -> p0f TCP SYN socket tuning          |
       +-------------------------------------------------------------+
```

`aoni-browser` uses strict **Inversion of Control (IoC)**. It does not fork or wrap the core client in heavyweight proxies. Instead, it leverages the public `aoni.ExtensionConfig` contract:
1. **`WrapTLSClient`**: Intercepts dialed TCP streams to execute `HandshakeUTLS` (uTLS presets, ECH, cert compression, SPKI verification).
2. **`OverrideH2Settings`**: Dictates exact browser HTTP/2 SETTINGS frame parameters (table size, stream windows, max header list size).
3. **`HeaderOrder`**: Governs strict `:method, :authority, :scheme, :path` ordering and header case preservation.
4. **`ConnFilters`**: Configures L4 socket options (`TCP_MAXSEG`, `SO_RCVBUF`, `IP_TTL`) for p0f OS spoofing.

## License

This project is licensed under the **BSD 3-Clause License**. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Lemon4ksan. All rights reserved.
