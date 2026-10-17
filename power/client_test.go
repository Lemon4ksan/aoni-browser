// Copyright (c) 2026 Lemon4ksan All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package power

import (
	"testing"

	"github.com/lemon4ksan/aoni"
	"github.com/lemon4ksan/aoni/option"
	"github.com/lemon4ksan/foundation/testing/assert"
)

// *aoni.Client must keep satisfying IdleCloser.
var _ IdleCloser = (*aoni.Client)(nil)

type fakeIdleCloser struct{ closed int }

func (f *fakeIdleCloser) CloseIdleConnections() { f.closed++ }

func TestWatcher_DropIdleOnSuspend(t *testing.T) {
	t.Parallel()

	w := NewWatcher(0)
	defer w.Close()

	fake := &fakeIdleCloser{}
	w.DropIdleOnSuspend(fake)
	w.DropIdleOnSuspend(nil) // must be ignored

	w.notifySuspendAndResume()

	assert.Equal(t, 1, fake.closed)
}

func TestWatcher_CloseTiedToClientLifecycle(t *testing.T) {
	t.Parallel()

	w := NewWatcher(0)

	var closed int

	client := aoni.NewClient(nil, option.WithOnClose(func() {
		w.Close()

		closed++
	}))

	client.Close()
	client.Close() // hooks are drained after the first Close

	assert.Equal(t, 1, closed)
}
