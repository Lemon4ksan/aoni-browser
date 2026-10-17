// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package power

// IdleCloser is implemented by clients able to drop idle keep-alive connections,
// such as *aoni.Client.
type IdleCloser interface {
	CloseIdleConnections()
}

// DropIdleOnSuspend registers a suspend callback that closes the idle connections of c.
//
// After a laptop sleeps, pooled keep-alive sockets silently rot; flushing the pool on suspend avoids
// "connection reset by peer" errors and 15-second write timeouts on the first requests after wake-up.
//
// The watcher runs its own goroutine, so tie its lifetime to the client with the core lifecycle hook:
//
//	w := power.NewWatcher(0)
//	client := aoni.NewClient(nil, option.WithOnClose(w.Close))
//	w.DropIdleOnSuspend(client)
func (w *Watcher) DropIdleOnSuspend(c IdleCloser) {
	if c == nil {
		return
	}

	w.OnSuspend(c.CloseIdleConnections)
}
