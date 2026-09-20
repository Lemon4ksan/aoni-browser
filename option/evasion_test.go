// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package option_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni-browser"
	"github.com/lemon4ksan/aoni-browser/fingerprint"
	"github.com/lemon4ksan/aoni-browser/fingerprint/ja4"
	"github.com/lemon4ksan/aoni-browser/option"
	"github.com/lemon4ksan/aoni-browser/privacypass"
	"github.com/lemon4ksan/aoni-browser/profile"
	aonioption "github.com/lemon4ksan/aoni/option"
	"github.com/lemon4ksan/foundation/net/tls/cert"
	"github.com/lemon4ksan/foundation/testing/assert"
	"github.com/lemon4ksan/foundation/testing/require"
)

func generateTestCert(t *testing.T, host string) (tls.Certificate, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Aoni Test Corp"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	spkiHash := sha256.Sum256(parsedCert.RawSubjectPublicKeyInfo)
	spkiPin := base64.StdEncoding.EncodeToString(spkiHash[:])

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return tlsCert, spkiPin
}

func TestOption_TLSFingerprint(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.WithTLSFingerprint(browser.BrowserChrome)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.Equal(t, browser.BrowserChrome, btc.BrowserID)
	assert.Nil(t, btc.HelloID)
}

func TestOption_TLSClientHelloID(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.WithTLSClientHelloID(utls.HelloFirefox_120)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	require.NotNil(t, btc.HelloID)
	assert.Equal(t, utls.HelloFirefox_120, *btc.HelloID)
}

func TestOption_PersonaStruct(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.WithPersonaStruct(fingerprint.PersonaChrome120Windows)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	require.NotNil(t, btc.HelloID)
	assert.Equal(t, utls.HelloChrome_120, *btc.HelloID)
	assert.NotEmpty(t, cfg.Ext.HeaderOrder)
	assert.NotEmpty(t, cfg.Ext.OverrideH2Settings)
}

func TestOption_0RTT_And_SessionCache(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.With0RTT(true)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.True(t, btc.Enable0RTT)
}

func TestOption_CertCompression(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.WithCertCompression(cert.CompressionBrotli, cert.CompressionZstd)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.Len(t, btc.CertCompression, 2)
	assert.Equal(t, cert.CompressionBrotli, btc.CertCompression[0])
	assert.Equal(t, cert.CompressionZstd, btc.CertCompression[1])
}

func TestOption_ECHConfig(t *testing.T) {
	t.Parallel()

	rawECH := []byte{0x00, 0x10, 0xfe, 0x0d, 0x01, 0x02, 0x03}
	cfg := aoni.Config{}
	option.WithECHConfig(rawECH)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.Equal(t, rawECH, btc.ECHConfigList)
}

func TestOption_ECHConfigBase64(t *testing.T) {
	t.Parallel()

	rawECH := []byte{0x00, 0x10, 0xfe, 0x0d, 0x01, 0x02, 0x03}
	b64 := base64.StdEncoding.EncodeToString(rawECH)

	cfg := aoni.Config{}
	option.WithECHConfigBase64(b64)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.Equal(t, rawECH, btc.ECHConfigList)
}

func TestOption_AutoECH(t *testing.T) {
	t.Parallel()

	cfg := aoni.Config{}
	option.WithAutoECH(true)(&cfg)

	btc := profile.GetOrInitBrowserTLS(&cfg)
	assert.True(t, btc.AutoECH)
}

func TestOption_CertificatePinning_Match(t *testing.T) {
	t.Parallel()

	cert, spkiPin := generateTestCert(t, "127.0.0.1")

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pin-ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()
	defer server.Close()

	client := aoni.NewClient(nil,
		option.WithCertificatePin("127.0.0.1", spkiPin),
		aonioption.WithInsecureSkipVerify(), // Skip CA verification to test explicit SPKI pin logic
	)

	resp, err := client.Request(t.Context(), http.MethodGet, server.URL)
	require.NoError(t, err)
	defer aoni.CloseResponse(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestOption_CertificatePinning_Mismatch(t *testing.T) {
	t.Parallel()

	cert, _ := generateTestCert(t, "127.0.0.1")

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()
	defer server.Close()

	bogusPin := "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="

	client := aoni.NewClient(nil,
		option.WithCertificatePin("127.0.0.1", bogusPin),
		aonioption.WithInsecureSkipVerify(),
	)

	_, err := client.Request(t.Context(), http.MethodGet, server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate pinning verification failed")
}

func TestOption_JA4Callback(t *testing.T) {
	t.Parallel()

	cert, _ := generateTestCert(t, "127.0.0.1")

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()
	defer server.Close()

	var (
		capturedReport ja4.Report
		once           sync.Once
	)
	reportReceived := make(chan struct{})

	client := aoni.NewClient(nil,
		option.WithChrome(),
		option.WithJA4Callback(func(r ja4.Report) {
			once.Do(func() {
				capturedReport = r
				close(reportReceived)
			})
		}),
		aonioption.WithInsecureSkipVerify(),
	)

	resp, err := client.Request(t.Context(), http.MethodGet, server.URL)
	require.NoError(t, err)
	defer aoni.CloseResponse(resp)

	select {
	case <-reportReceived:
		assert.NotEmpty(t, capturedReport.JA4)
	case <-time.After(2 * time.Second):
		t.Fatal("JA4 callback was not invoked within timeout")
	}
}

func TestOption_PacketPadding(t *testing.T) {
	t.Parallel()

	padding := fingerprint.PaddingConfig{
		MaxSegmentSize:  1200,
		MinPaddingBytes: 16,
		MaxPaddingBytes: 32,
		PaddingHeader:   "X-DPI-Padding",
	}

	cfg := aoni.Config{}
	option.WithPacketPadding(padding)(&cfg)

	assert.NotEmpty(t, cfg.Network.ConnFilters)
	assert.NotEmpty(t, cfg.Defaults.DefaultMods)
}

func TestOption_PersonaPresets(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"chrome", "firefox", "safari", "chrome_mobile"} {
		cfg := aoni.Config{}
		option.WithPersona(name)(&cfg)

		btc := profile.GetOrInitBrowserTLS(&cfg)
		require.NotNil(t, btc)
	}
}

func TestOption_PrivacyPass(t *testing.T) {
	t.Parallel()

	prov := privacypass.NewStaticProvider()
	cfg := aoni.Config{}
	option.WithPrivacyPass(prov)(&cfg)

	assert.NotNil(t, cfg.Ext.Extra)
}
