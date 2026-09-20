// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package challenge

import (
	"net/http"

	"github.com/lemon4ksan/foundation/generic"
)

// Transport wraps an underlying [http.RoundTripper] and transparently intercepts and resolves
// anti-bot challenge pages (e.g. Cloudflare Turnstile, Privacy Pass, or CAPTCHA) using a [ChallengePipeline].
type Transport struct {
	base     http.RoundTripper
	pipeline *ChallengePipeline
}

// NewTransport constructs a challenge-resolving [Transport] decorating the provided base round tripper.
func NewTransport(base http.RoundTripper, pipeline *ChallengePipeline) *Transport {
	return &Transport{
		base:     generic.Ternary(base != nil, base, http.DefaultTransport),
		pipeline: pipeline,
	}
}

// RoundTrip executes the HTTP transaction and runs challenge detection/solving against the response.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || t.pipeline == nil {
		return resp, err
	}

	solved, finalResp, solveErr := t.pipeline.SolveCascading(req, resp)
	if solveErr != nil {
		return nil, solveErr
	}
	if solved {
		return finalResp, nil
	}

	return resp, nil
}

// Unwrap returns the underlying [http.RoundTripper] wrapped by this transport.
func (t *Transport) Unwrap() http.RoundTripper {
	return t.base
}
