// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package browser

// BrowserID represents a generic browser persona.
type BrowserID int

const (
	BrowserNone BrowserID = iota
	BrowserChrome
	BrowserFirefox
	BrowserSafari
	BrowserEdge
)
