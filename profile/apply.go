// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profile

import (
	"github.com/lemon4ksan/foundation/silicon/pool"
	utls "github.com/refraction-networking/utls"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni-browser/fingerprint/profiles"
	"github.com/lemon4ksan/aoni/pipeline"
)

var headerMapPool = pool.NewPerPStorage(func() map[string]string {
	return make(map[string]string, 16)
})

func acquireHeaderMap() map[string]string {
	return headerMapPool.Get()
}

func releaseHeaderMap(m map[string]string) {
	clear(m)
	headerMapPool.Put(m)
}

// ApplyTLSVariantToConfig maps uTLS ClientHello specifications, presets, and QUIC TLS parameters
// from a browser profile variant ([profiles.Variant]) into the target client configuration.
func ApplyTLSVariantToConfig(cfg *aoni.Config, variant *profiles.Variant) {
	if variant == nil {
		return
	}

	btc := GetOrInitBrowserTLS(cfg)

	if variant.HelloSpec != nil {
		btc.HelloSpec = variant.HelloSpec
		btc.HelloID = nil
	} else if variant.HelloID != (utls.ClientHelloID{}) {
		id := variant.HelloID
		btc.HelloID = &id
		btc.HelloSpec = nil
	}
}

// ApplyHTTPVariantToConfig translates HTTP/2 SETTINGS frames, HTTP/3 QUIC transport limits,
// default browser request headers, and method-specific header ordering rules into the client configuration.
func ApplyHTTPVariantToConfig(cfg *aoni.Config, variant *profiles.Variant, os profiles.OSKey) {
	if variant == nil {
		return
	}

	h2Settings, _ := ApplyHTTPSettings(variant)
	if h2Settings != nil {
		cfg.Ext.OverrideH2Settings = map[uint16]uint32{
			1: h2Settings.HeaderTableSize,
			2: h2Settings.EnablePush,
			3: h2Settings.MaxConcurrentStreams,
			4: h2Settings.InitialWindowSize,
			5: h2Settings.MaxFrameSize,
			6: h2Settings.MaxHeaderListSize,
		}
	}

	// We apply the GET header order globally.
	// For method-specific overrides, setOrderedHeaders will run in the Pre-flight request mods.
	cfg.Ext.HeaderOrder = BuildHeaderOrder(variant, os, "GET")
	cfg.Defaults.Headers = PopulateHeaders(cfg.Defaults.Headers, variant, os)
}

// ApplyProfileHeaders injects method-specific browser headers, WebKit/Gecko multipart boundary lines,
// and method-tailored header serialization sequences into the outgoing request contract.
func ApplyProfileHeaders(req aoni.Request, variant *profiles.Variant, os profiles.OSKey) {
	if variant == nil {
		return
	}

	if variant.InsertHeaders != nil {
		headersMap := acquireHeaderMap()
		defer releaseHeaderMap(headersMap)

		stdReq := req.HTTPRequest()
		if stdReq != nil {
			for k, v := range stdReq.Header {
				if len(v) > 0 {
					headersMap[k] = v[0]
				}
			}
		} else if req.Headers() != nil {
			for k, v := range req.Headers() {
				kStr := string(k)
				if _, exists := headersMap[kStr]; !exists {
					headersMap[kStr] = string(v)
				}
			}
		}

		variant.InsertHeaders(headersMap, req.Method())

		for k, v := range headersMap {
			if len(k) > 0 && k[0] == ':' {
				continue
			}

			if v != "" && req.Header(k) == "" {
				req.SetHeader(k, v)
			}
		}
	}

	if variant.BoundaryFunc != nil {
		cfg := pipeline.GetOrInitRequestConfig(req)
		cfg.MultipartBoundary = variant.BoundaryFunc()
	}

	if variant.HeaderCache != nil {
		setOrderedHeaders(req, variant, os)
	}
}

// setOrderedHeaders calculates and attaches method-specific ordered header keys to the request config.
func setOrderedHeaders(req aoni.Request, variant *profiles.Variant, os profiles.OSKey) {
	cfg := pipeline.GetOrInitRequestConfig(req)
	cfg.OrderedHeaders = BuildHeaderOrder(variant, os, req.Method())
}
