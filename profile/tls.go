// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profile

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni-browser"
	"github.com/lemon4ksan/aoni-browser/fingerprint"
	"github.com/lemon4ksan/aoni-browser/fingerprint/ja4"
	"github.com/lemon4ksan/mach/proto/dns/svcb"
	"github.com/lemon4ksan/foundation/net/tls/cert"
)

// BrowserTLSKey is the key under which [BrowserTLSConfig] is stored in [aoni.Config.Ext.Extra].
const BrowserTLSKey = "browser.tls"

// BrowserTLSConfig centralizes all TLS emulation, uTLS presets, ECH, cert compression,
// certificate pinning, session caching, and JA4 fingerprinting for aoni-browser.
type BrowserTLSConfig struct {
	BrowserID       browser.BrowserID
	HelloID         *utls.ClientHelloID
	HelloSpec       *utls.ClientHelloSpec
	SpecProvider    fingerprint.ClientHelloSpecProvider
	SessionCache    fingerprint.SessionCache
	Enable0RTT      bool
	CertCompression []cert.CompressionAlgorithm
	CertificatePins map[string][]string // domain -> slice of normalized base64 SPKI SHA-256 hashes
	ECHConfigList   []byte
	AutoECH         bool
	JA4Callback     func(ja4.Report)
}

// Clone implements deep copying for [aoni.Config.Ext.Clone].
func (c *BrowserTLSConfig) Clone() any {
	if c == nil {
		return nil
	}

	cloned := *c

	if c.HelloID != nil {
		id := *c.HelloID
		cloned.HelloID = &id
	}

	if len(c.CertCompression) > 0 {
		cloned.CertCompression = append([]cert.CompressionAlgorithm(nil), c.CertCompression...)
	}

	if c.CertificatePins != nil {
		cloned.CertificatePins = make(map[string][]string, len(c.CertificatePins))
		for k, v := range c.CertificatePins {
			cloned.CertificatePins[k] = append([]string(nil), v...)
		}
	}

	if len(c.ECHConfigList) > 0 {
		cloned.ECHConfigList = append([]byte(nil), c.ECHConfigList...)
	}

	return &cloned
}

// GetOrInitBrowserTLS retrieves or initializes the active [BrowserTLSConfig] in [aoni.Config].
func GetOrInitBrowserTLS(cfg *aoni.Config) *BrowserTLSConfig {
	if cfg.Ext.Extra == nil {
		cfg.Ext.Extra = make(map[string]any)
	}

	if v, ok := cfg.Ext.Extra[BrowserTLSKey]; ok {
		if btc, ok := v.(*BrowserTLSConfig); ok {
			return btc
		}
	}

	btc := &BrowserTLSConfig{
		CertificatePins: make(map[string][]string),
	}
	cfg.Ext.Extra[BrowserTLSKey] = btc
	EnsureWrapTLSClient(cfg)

	return btc
}

// EnsureWrapTLSClient ensures that [cfg.Ext.WrapTLSClient] is wired to the browser TLS orchestrator.
func EnsureWrapTLSClient(cfg *aoni.Config) {
	cfg.Ext.WrapTLSClient = func(ctx context.Context, conn net.Conn, baseCfg *tls.Config, addr string) (net.Conn, error) {
		btc := GetOrInitBrowserTLS(cfg)
		return HandshakeUTLS(ctx, conn, baseCfg, addr, btc, cfg)
	}
}

// BrowserIDToHelloID maps [browser.BrowserID] to the corresponding uTLS [utls.ClientHelloID].
func BrowserIDToHelloID(id browser.BrowserID) utls.ClientHelloID {
	switch id {
	case browser.BrowserChrome:
		return utls.HelloChrome_Auto
	case browser.BrowserFirefox:
		return utls.HelloFirefox_Auto
	case browser.BrowserSafari:
		return utls.HelloSafari_Auto
	case browser.BrowserEdge:
		return utls.HelloEdge_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// HandshakeUTLS performs the complete uTLS handshake honoring all evasion options.
func HandshakeUTLS(
	ctx context.Context,
	conn net.Conn,
	baseCfg *tls.Config,
	addr string,
	btc *BrowserTLSConfig,
	rootCfg *aoni.Config,
) (net.Conn, error) {
	if baseCfg == nil {
		baseCfg = &tls.Config{}
	}

	serverName := baseCfg.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			serverName = host
		} else {
			serverName = addr
		}
	}

	insecure := baseCfg.InsecureSkipVerify
	if rootCfg != nil && rootCfg.Engine.InsecureSkipVerify {
		insecure = true
	}

	uCfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		NextProtos:         baseCfg.NextProtos,
	}

	// 1. Session Resumption & 0-RTT
	if btc.Enable0RTT || btc.SessionCache != nil {
		uCfg.SessionTicketsDisabled = false
		if btc.SessionCache != nil {
			uCfg.ClientSessionCache = btc.SessionCache
		} else {
			uCfg.ClientSessionCache = utls.NewLRUClientSessionCache(64)
		}
	}

	// 2. Encrypted Client Hello (ECH / RFC 9484)
	if len(btc.ECHConfigList) > 0 {
		uCfg.EncryptedClientHelloConfigList = btc.ECHConfigList
		uCfg.MinVersion = utls.VersionTLS13
	} else if btc.AutoECH && serverName != "" {
		if echBytes := resolveAutoECH(ctx, rootCfg, serverName); len(echBytes) > 0 {
			uCfg.EncryptedClientHelloConfigList = echBytes
			uCfg.MinVersion = utls.VersionTLS13
		}
	}

	// 3. Certificate & SPKI Pinning (RFC 7469)
	if len(btc.CertificatePins) > 0 {
		pins := getPinsForDomain(btc.CertificatePins, serverName)
		if len(pins) > 0 {
			uCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return verifySPKIPins(rawCerts, pins, serverName)
			}
		}
	}

	// 4. Construct uConn with ClientHello precedence:
	//    SpecProvider > HelloSpec > HelloID > BrowserID > HelloChrome_Auto
	var uConn *utls.UConn

	if btc.SpecProvider != nil {
		spec, err := btc.SpecProvider.ClientHelloSpec()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("aoni/browser: failed to obtain ClientHelloSpec: %w", err)
		}
		uConn = utls.UClient(conn, uCfg, utls.HelloCustom)
		if err := uConn.ApplyPreset(spec); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("aoni/browser: failed to apply ClientHelloSpec: %w", err)
		}
	} else if btc.HelloSpec != nil {
		uConn = utls.UClient(conn, uCfg, utls.HelloCustom)
		if err := uConn.ApplyPreset(btc.HelloSpec); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("aoni/browser: failed to apply variant HelloSpec: %w", err)
		}
	} else if btc.HelloID != nil {
		uConn = utls.UClient(conn, uCfg, *btc.HelloID)
	} else if btc.BrowserID != browser.BrowserNone {
		uConn = utls.UClient(conn, uCfg, BrowserIDToHelloID(btc.BrowserID))
	} else {
		uConn = utls.UClient(conn, uCfg, utls.HelloChrome_Auto)
	}

	// 5. Apply RFC 8879 Certificate Compression if configured
	if len(btc.CertCompression) > 0 {
		applyCertCompression(uConn, btc.CertCompression)
	}

	// 6. Clean up ECH extensions if ECH is not active
	if len(uCfg.EncryptedClientHelloConfigList) == 0 {
		removeECHExtensions(uConn)
	}

	// 7. Execute TLS Handshake
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// 8. JA4 Telemetry Dispatch
	if btc.JA4Callback != nil || (rootCfg != nil && rootCfg.Ext.JA4Callback != nil) {
		report := extractJA4FromUConn(uConn, uCfg.ServerName)
		if btc.JA4Callback != nil {
			btc.JA4Callback(report)
		}
		if rootCfg != nil && rootCfg.Ext.JA4Callback != nil {
			rootCfg.Ext.JA4Callback(report)
		}
	}

	return uConn, nil
}

// NormalizePin cleans and normalizes a public key pin into standard base64 format.
func NormalizePin(pin string) string {
	cleaned := strings.TrimSpace(pin)
	cleaned = strings.Trim(cleaned, `"`)

	lower := strings.ToLower(cleaned)
	if strings.HasPrefix(lower, "pin-sha256=") {
		cleaned = strings.Trim(cleaned[len("pin-sha256="):], `"`)
	} else if strings.HasPrefix(lower, "sha256/") {
		cleaned = cleaned[len("sha256/"):]
	}

	// If 64 hex characters (32 bytes), convert to base64
	if len(cleaned) == 64 {
		if raw, err := hex.DecodeString(cleaned); err == nil {
			return base64.StdEncoding.EncodeToString(raw)
		}
	}

	return cleaned
}

func getPinsForDomain(pins map[string][]string, serverName string) []string {
	if len(pins) == 0 || serverName == "" {
		return nil
	}

	serverName = strings.ToLower(serverName)
	if exact, ok := pins[serverName]; ok {
		return exact
	}

	// Match wildcard *.domain.com
	for pattern, list := range pins {
		pattern = strings.ToLower(pattern)
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .domain.com
			if strings.HasSuffix(serverName, suffix) {
				return list
			}
		}
	}

	return nil
}

func verifySPKIPins(rawCerts [][]byte, expectedPins []string, serverName string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("aoni/tls: no certificates presented by %s", serverName)
	}

	pinSet := make(map[string]struct{}, len(expectedPins))
	for _, p := range expectedPins {
		pinSet[NormalizePin(p)] = struct{}{}
	}

	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			continue
		}

		spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		b64 := base64.StdEncoding.EncodeToString(spkiHash[:])

		if _, matched := pinSet[b64]; matched {
			return nil
		}
	}

	return fmt.Errorf("aoni/tls: certificate pinning verification failed for %s: no SPKI hash matched configured pins", serverName)
}

func applyCertCompression(uConn *utls.UConn, algos []cert.CompressionAlgorithm) {
	if uConn.Extensions == nil {
		return
	}

	utlsAlgos := make([]utls.CertCompressionAlgo, 0, len(algos))
	for _, a := range algos {
		switch a {
		case cert.CompressionBrotli:
			utlsAlgos = append(utlsAlgos, utls.CertCompressionBrotli)
		case cert.CompressionZstd:
			utlsAlgos = append(utlsAlgos, utls.CertCompressionZstd)
		case cert.CompressionZlib:
			utlsAlgos = append(utlsAlgos, utls.CertCompressionZlib)
		}
	}

	if len(utlsAlgos) == 0 {
		return
	}

	for _, ext := range uConn.Extensions {
		if cExt, ok := ext.(*utls.UtlsCompressCertExtension); ok {
			cExt.Algorithms = utlsAlgos
			return
		}
	}

	uConn.Extensions = append(uConn.Extensions, &utls.UtlsCompressCertExtension{
		Algorithms: utlsAlgos,
	})
}

func removeECHExtensions(uConn *utls.UConn) {
	if len(uConn.Extensions) == 0 {
		return
	}

	filtered := make([]utls.TLSExtension, 0, len(uConn.Extensions))
	for _, ext := range uConn.Extensions {
		if gExt, ok := ext.(*utls.GenericExtension); ok {
			if gExt.Id == fingerprint.ExtensionTypeEncryptedClientHello ||
				gExt.Id == fingerprint.ExtensionTypeECHOuterExtensions {
				continue
			}
		}
		filtered = append(filtered, ext)
	}
	uConn.Extensions = filtered
}

func resolveAutoECH(ctx context.Context, rootCfg *aoni.Config, serverName string) []byte {
	if rootCfg == nil {
		return nil
	}

	// Try DNS resolver if configured
	if resolver, ok := rootCfg.Network.DNSResolver.(interface {
		LookupHTTPS(ctx context.Context, host string, port uint16) ([]*svcb.Record, error)
	}); ok {
		records, err := resolver.LookupHTTPS(ctx, serverName, 443)
		if err == nil {
			for _, r := range records {
				if len(r.ECHConfig()) > 0 {
					return r.ECHConfig()
				}
			}
		}
	}

	return nil
}

func extractJA4FromUConn(uConn *utls.UConn, serverName string) ja4.Report {
	cs := uConn.ConnectionState()
	alpn := cs.NegotiatedProtocol

	var (
		ciphers  []uint16
		exts     []uint16
		versions []uint16
		sigAlgs  []uint16
		sni      = serverName != ""
	)

	if uConn.HandshakeState.Hello != nil {
		ciphers = uConn.HandshakeState.Hello.CipherSuites
		versions = uConn.HandshakeState.Hello.SupportedVersions
		for _, sa := range uConn.HandshakeState.Hello.SupportedSignatureAlgorithms {
			sigAlgs = append(sigAlgs, uint16(sa))
		}
		if uConn.HandshakeState.Hello.ServerName != "" {
			sni = true
		}
		if len(uConn.HandshakeState.Hello.Raw) > 0 {
			exts, _ = ja4.ParseExtensionsFromRaw(uConn.HandshakeState.Hello.Raw)
		}
	}

	if len(exts) == 0 && len(uConn.Extensions) > 0 {
		for _, e := range uConn.Extensions {
			if ge, ok := e.(*utls.GenericExtension); ok {
				exts = append(exts, ge.Id)
			}
		}
	}

	alpns := []string{alpn}
	if alpn == "" && len(cs.NegotiatedProtocol) > 0 {
		alpns = []string{cs.NegotiatedProtocol}
	}

	ja4String := ja4.ComputeJA4(ciphers, exts, versions, sni, alpns, sigAlgs)

	return ja4.Report{
		JA4:         ja4String,
		Protocol:    "tcp",
		Version:     fmt.Sprintf("%04x", cs.Version),
		SNI:         serverName,
		ALPN:        alpn,
		CipherCount: len(ciphers),
		ExtCount:    len(exts),
	}
}
