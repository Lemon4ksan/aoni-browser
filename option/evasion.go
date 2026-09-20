// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package option

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni-browser"
	"github.com/lemon4ksan/aoni-browser/fingerprint"
	"github.com/lemon4ksan/aoni-browser/fingerprint/ja4"
	"github.com/lemon4ksan/aoni-browser/fingerprint/p0f"
	"github.com/lemon4ksan/aoni-browser/fingerprint/profiles"
	"github.com/lemon4ksan/aoni-browser/fingerprint/profiles/chrome"
	"github.com/lemon4ksan/aoni-browser/fingerprint/profiles/firefox"
	"github.com/lemon4ksan/aoni-browser/fingerprint/profiles/safari"
	"github.com/lemon4ksan/aoni-browser/privacypass"
	"github.com/lemon4ksan/aoni-browser/profile"
	"github.com/lemon4ksan/aoni-browser/resiliency/challenge"
	"github.com/lemon4ksan/aoni/cookie"
	"github.com/lemon4ksan/aoni/mod"
	aonioption "github.com/lemon4ksan/aoni/option"
	"github.com/lemon4ksan/foundation/generic"
	"github.com/lemon4ksan/foundation/net/tls/cert"
)

// WithChrome configures a production-grade, zero-configuration Google Chrome browser profile.
//
// Automatically synchronizes all layers of the networking stack to match Chromium:
//   - TLS: uTLS Chrome 120+ ClientHello with GREASE extensions, ALPN (h2, http/1.1), and TLS 1.3 key shares.
//   - HTTP/2 & HTTP/3: Chrome SETTINGS frames, WINDOW_UPDATE parameters, and stream priorities.
//   - Headers & Client Hints: Correct Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, and Accept headers.
//   - Security & Privacy: 0-RTT session resumption, Auto-ECH DNS probing, and RFC 8879 cert compression.
//   - Cookies: Automatic [cookie.ProxyIsolatedJar] with CHIPS partitioning.
func WithChrome() aoni.ClientOption {
	return func(cfg *aoni.Config) {
		WithProfileVariant(chrome.Desktop, profiles.Windows)(cfg)
		With0RTT(true)(cfg)
		WithAutoECH(true)(cfg)
		WithCertCompression(cert.CompressionBrotli, cert.CompressionZstd)(cfg)

		if cfg.Engine.CookieJar == nil {
			cfg.Engine.CookieJar = cookie.NewProxyIsolatedJar()
		}

		hints := fingerprint.BuildClientHintsForOS(chrome.UserAgentWindows, profiles.Windows)

		cfg.Defaults.DefaultMods = append(cfg.Defaults.DefaultMods, mod.Custom(func(req aoni.Request) {
			hints.ApplyHeaders(req.SetHeader)
		}))
	}
}

// WithChromeMobile configures a zero-configuration Chrome Android mobile persona.
//
// Injects mobile User-Agent strings and Sec-CH-UA mobile Client Hints (`?1`).
func WithChromeMobile() aoni.ClientOption {
	return func(cfg *aoni.Config) {
		WithProfileVariant(chrome.Mobile, profiles.Android)(cfg)
		With0RTT(true)(cfg)
		WithAutoECH(true)(cfg)
		WithCertCompression(cert.CompressionBrotli, cert.CompressionZstd)(cfg)

		if cfg.Engine.CookieJar == nil {
			cfg.Engine.CookieJar = cookie.NewProxyIsolatedJar()
		}

		hints := fingerprint.BuildClientHintsForOS(chrome.UserAgentAndroid, profiles.Android)

		cfg.Defaults.DefaultMods = append(cfg.Defaults.DefaultMods, mod.Custom(func(req aoni.Request) {
			hints.ApplyHeaders(req.SetHeader)
		}))
	}
}

// WithFirefox configures a zero-configuration Mozilla Firefox browser persona.
//
// Sets Firefox TLS cipher suite ordering, HTTP/2 SETTINGS framing, and Firefox-specific
// Accept headers without Chromium Client Hints.
func WithFirefox() aoni.ClientOption {
	return func(cfg *aoni.Config) {
		WithProfileVariant(firefox.Desktop, profiles.Windows)(cfg)
		With0RTT(true)(cfg)
		WithAutoECH(true)(cfg)
		WithCertCompression(cert.CompressionBrotli, cert.CompressionZstd)(cfg)

		if cfg.Engine.CookieJar == nil {
			cfg.Engine.CookieJar = cookie.NewProxyIsolatedJar()
		}
	}
}

// WithSafari configures a zero-configuration Apple Safari macOS browser persona.
//
// Synchronizes Apple TLS ClientHello signatures, ALPN negotiation, and WebKit HTTP/2 framing.
func WithSafari() aoni.ClientOption {
	return func(cfg *aoni.Config) {
		WithProfileVariant(safari.Desktop, profiles.MacOS)(cfg)
		With0RTT(true)(cfg)
		WithCertCompression(cert.CompressionBrotli)(cfg)

		if cfg.Engine.CookieJar == nil {
			cfg.Engine.CookieJar = cookie.NewProxyIsolatedJar()
		}
	}
}

// WithTLSFingerprint selects a pre-defined [aoni.BrowserID] uTLS ClientHello profile.
func WithTLSFingerprint(browserID browser.BrowserID) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		if browserID == browser.BrowserNone {
			return
		}

		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.BrowserID = browserID
		btc.HelloID = nil
		btc.HelloSpec = nil
		btc.SpecProvider = nil
	}
}

// WithTLSClientHelloID explicitly assigns a low-level [utls.ClientHelloID] preset.
func WithTLSClientHelloID(id utls.ClientHelloID) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.HelloID = &id
		btc.HelloSpec = nil
		btc.SpecProvider = nil
	}
}

// WithPersonaStruct configures TLS ClientHello ID, HTTP/2 settings, and header order from a [fingerprint.Persona].
func WithPersonaStruct(p fingerprint.Persona) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		WithTLSClientHelloID(p.TLSID)(cfg)
		cfg.Ext.HeaderOrder = p.HeaderOrder
		if p.UserAgent != "" {
			if cfg.Defaults.Headers == nil {
				cfg.Defaults.Headers = make(http.Header)
			}
			cfg.Defaults.Headers.Set("User-Agent", p.UserAgent)
		}
		if p.H2Settings.HeaderTableSize > 0 || p.H2Settings.MaxFrameSize > 0 {
			cfg.Ext.OverrideH2Settings = map[uint16]uint32{
				1: p.H2Settings.HeaderTableSize,
				2: p.H2Settings.EnablePush,
				3: p.H2Settings.MaxConcurrentStreams,
				4: p.H2Settings.InitialWindowSize,
				5: p.H2Settings.MaxFrameSize,
				6: p.H2Settings.MaxHeaderListSize,
			}
		}
		if p.P0fSignature != nil {
			WithP0fSignature(p.P0fSignature)(cfg)
		}
	}
}

// WithTLSClientHelloSpecProvider configures a dynamic callback to generate customized uTLS ClientHello specifications.
func WithTLSClientHelloSpecProvider(provider fingerprint.ClientHelloSpecProvider) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.SpecProvider = provider
		btc.HelloSpec = nil
		btc.HelloID = nil
	}
}

// WithProfileVariant applies a full browser profile variant (TLS, HTTP/2 SETTINGS, headers) for a target OS.
func WithProfileVariant(variant *profiles.Variant, os profiles.OSKey) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		if variant == nil {
			return
		}

		profile.ApplyTLSVariantToConfig(cfg, variant)
		profile.ApplyHTTPVariantToConfig(cfg, variant, os)

		cfg.Defaults.DefaultMods = append(cfg.Defaults.DefaultMods, mod.Custom(func(req aoni.Request) {
			profile.ApplyProfileHeaders(req, variant, os)
		}))
	}
}

// WithBrowserProfile selects a pre-defined browser profile and tunes it for the specified operating system.
func WithBrowserProfile(browserID browser.BrowserID, os profiles.OSKey) aoni.ClientOption {
	var variant *profiles.Variant

	switch browserID {
	case browser.BrowserFirefox:
		variant = generic.Ternary(os.IsMobile(), firefox.Mobile, firefox.Desktop)
	default:
		variant = generic.Ternary(os.IsMobile(), chrome.Mobile, chrome.Desktop)
	}

	return WithProfileVariant(variant, os)
}

// WithP0fSignature configures TCP/IP SYN packet fingerprint spoofing (TTL, Window Size, MSS, WScale, ECN).
//
// Allows mimicking specific host OS TCP stacks (Windows, Linux, iOS, macOS) to defeat p0f L4 passive OS detection.
func WithP0fSignature(sig *p0f.Signature) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		cfg.Network.ConnFilters = append(cfg.Network.ConnFilters, func(ctx context.Context, conn net.Conn, host string, dialCfg *aoni.DialConfig) (net.Conn, error) {
			spoofer := p0f.NewSpoofer(sig)
			_ = spoofer.Apply(conn)
			return conn, nil
		})
	}
}

// WithSessionCache assigns an isolated TLS session cache for TLS 1.2/1.3 session resumption.
func WithSessionCache(cache fingerprint.SessionCache) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.SessionCache = cache
	}
}

// With0RTT enables TLS 1.3 and QUIC 0-RTT (Early Data) session resumption (RFC 8446 / RFC 9001).
//
// Sends request payloads inside the initial handshake packet when reconnecting to known servers,
// eliminating one round-trip time.
func With0RTT(enable bool) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.Enable0RTT = enable
	}
}

// WithCertCompression enables RFC 8879 TLS Certificate Compression during handshakes.
//
// Compresses remote server certificate chains using Brotli or Zstandard to minimize TLS packet count.
func WithCertCompression(algos ...cert.CompressionAlgorithm) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.CertCompression = append(btc.CertCompression, algos...)
	}
}

// WithCertificatePin pins a SHA-256 certificate public key hash for a target domain.
func WithCertificatePin(domain, hash string) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		d := strings.ToLower(strings.TrimSpace(domain))
		norm := profile.NormalizePin(hash)
		btc.CertificatePins[d] = append(btc.CertificatePins[d], norm)
	}
}

// WithCertificatePins registers multiple domain certificate pins (RFC 7469).
func WithCertificatePins(pins map[string][]string) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		for d, hs := range pins {
			dLower := strings.ToLower(strings.TrimSpace(d))
			for _, h := range hs {
				btc.CertificatePins[dLower] = append(btc.CertificatePins[dLower], profile.NormalizePin(h))
			}
		}
	}
}

// WithSPKIPin registers an RFC 7469 §2.4 Subject Public Key Info (SPKI) SHA-256 fingerprint pin for domain.
func WithSPKIPin(domain, pin string) aoni.ClientOption {
	return WithCertificatePin(domain, pin)
}

// WithPinnedSPKI registers multiple RFC 7469 §2.4 SPKI SHA-256 fingerprint pins for a domain.
func WithPinnedSPKI(domain string, pins ...string) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		for _, pin := range pins {
			WithCertificatePin(domain, pin)(cfg)
		}
	}
}

// WithECHConfig sets raw RFC 9484 TLS 1.3 Encrypted Client Hello (ECH) bytes to encrypt the Server Name Indication (SNI).
func WithECHConfig(raw []byte) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.ECHConfigList = raw
	}
}

// WithECHConfigBase64 parses and sets base64-encoded ECHConfigList parameters.
func WithECHConfigBase64(rawBase64 string) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		decoded, err := fingerprint.ParseECHConfigBase64(rawBase64)
		if err == nil {
			btc := profile.GetOrInitBrowserTLS(cfg)
			btc.ECHConfigList = decoded
		}
	}
}

// WithAutoECH enables automatic DNS HTTPS (Type 65 / RFC 9460) record lookup to discover and apply ECH keys dynamically.
func WithAutoECH(enable bool) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.AutoECH = enable
	}
}

// WithPacketPadding configures pseudo-random HTTP/2-3 frame padding to prevent traffic length analysis attacks.
func WithPacketPadding(padding fingerprint.PaddingConfig) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		if padding.MaxSegmentSize > 0 {
			cfg.Network.ConnFilters = append(cfg.Network.ConnFilters, func(_ context.Context, conn net.Conn, _ string, _ *aoni.DialConfig) (net.Conn, error) {
				return aoni.ApplyMSSLimit(conn, padding.MaxSegmentSize), nil
			})
		}

		if padding.MinPaddingBytes > 0 || padding.MaxPaddingBytes > 0 {
			cfg.Defaults.DefaultMods = append(cfg.Defaults.DefaultMods, mod.Custom(func(req aoni.Request) {
				hdrName := fingerprint.PaddingHeaderName(padding)
				padBytes := fingerprint.GeneratePadding(padding)
				if len(padBytes) > 0 {
					req.SetHeader(hdrName, base64.RawStdEncoding.EncodeToString(padBytes))
				}
			}))
		}
	}
}

// WithJA4Callback registers a telemetry callback invoked with computed [ja4.Report] signatures for each TLS connection.
func WithJA4Callback(fn func(ja4.Report)) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		btc := profile.GetOrInitBrowserTLS(cfg)
		btc.JA4Callback = fn
		cfg.Ext.JA4Callback = func(report interface{}) {
			if r, ok := report.(ja4.Report); ok {
				fn(r)
			}
		}
	}
}

// WithPersona configures a complete browser persona by common string name ("chrome", "firefox", "safari", "chrome_mobile").
func WithPersona(name string) aoni.ClientOption {
	switch strings.ToLower(name) {
	case "chrome", "google-chrome", "chromium":
		return WithChrome()
	case "firefox", "ff", "mozilla":
		return WithFirefox()
	case "safari", "apple":
		return WithSafari()
	case "chrome_mobile", "mobile", "android":
		return WithChromeMobile()
	default:
		return WithChrome()
	}
}

const (
	challengeDetectorKey            = "browser.challenge.detector"
	challengeSolverKey              = "browser.challenge.solver"
	challengeMiddlewareInstalledKey = "browser.challenge.installed"
)

// WithChallengeDetector registers a challenge detector for anti-bot interception.
func WithChallengeDetector(d challenge.Detector) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		if cfg.Ext.Extra == nil {
			cfg.Ext.Extra = make(map[string]any)
		}
		cfg.Ext.Extra[challengeDetectorKey] = d
		ensureChallengeMiddleware(cfg)
	}
}

// WithChallengeSolver registers an automated solver for anti-bot challenges.
func WithChallengeSolver(s challenge.Solver) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		if cfg.Ext.Extra == nil {
			cfg.Ext.Extra = make(map[string]any)
		}
		cfg.Ext.Extra[challengeSolverKey] = s
		ensureChallengeMiddleware(cfg)
	}
}

// WithPrivacyPass enables automatic RFC 9576 / RFC 9577 Privacy Pass & W3C Private State Tokens challenge solving.
func WithPrivacyPass(provider privacypass.TokenProvider) aoni.ClientOption {
	return func(cfg *aoni.Config) {
		solver := challenge.NewPrivateTokenSolver(provider, nil)
		WithChallengeDetector(challenge.DetectPrivateTokenChallenge)(cfg)
		WithChallengeSolver(solver)(cfg)
	}
}

func ensureChallengeMiddleware(cfg *aoni.Config) {
	if cfg.Ext.Extra == nil {
		cfg.Ext.Extra = make(map[string]any)
	}
	if _, ok := cfg.Ext.Extra[challengeMiddlewareInstalledKey]; ok {
		return
	}
	cfg.Ext.Extra[challengeMiddlewareInstalledKey] = true

	mid := func(next aoni.RequestDoer) aoni.RequestDoer {
		return aoni.DoerFunc(func(req aoni.Request) (aoni.Response, error) {
			resp, err := next.Do(req)
			if err != nil {
				return resp, err
			}

			rawResp := resp.HTTPResponse()
			if rawResp == nil {
				return resp, nil
			}

			detector := challenge.DefaultDetector
			if d, ok := cfg.Ext.Extra[challengeDetectorKey].(challenge.Detector); ok && d != nil {
				detector = d
			}

			solver, _ := cfg.Ext.Extra[challengeSolverKey].(challenge.Solver)
			if solver == nil {
				return resp, nil
			}

			detected, detErr := detector(rawResp)
			if !detected {
				return resp, nil
			}

			httpReq := req.HTTPRequest()
			if httpReq == nil {
				return resp, nil
			}

			solveErr := detErr
			if solveErr == nil {
				solveErr = err
			}

			newResp, sErr := solver.Solve(req.Context(), solveErr, httpReq)
			if sErr != nil {
				return nil, sErr
			}
			if newResp != nil {
				return aoni.NewStdResponse(newResp), nil
			}

			return resp, nil
		})
	}

	aonioption.WithMiddleware(mid)(cfg)
}
