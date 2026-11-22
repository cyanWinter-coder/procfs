// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build (aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris) && !js

package procfs

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcResourceSnapshot(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26236)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := p.ResourceSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if want, have := 26236, snap.PID; want != have {
		t.Errorf("want pid %d, have %d", want, have)
	}
	if want, have := uint64(90001), snap.StartTime; want != have {
		t.Errorf("want start time %d, have %d", want, have)
	}
	if want, have := uint64(1024), snap.Limits.OpenFiles; want != have {
		t.Errorf("want open files limit %d, have %d", want, have)
	}

	// FDInfos must be sorted numerically by fd number: a lexicographic
	// sort would order "10" before "2".
	wantFDs := []string{"0", "1", "2", "10"}
	if want, have := len(wantFDs), len(snap.FDInfos); want != have {
		t.Fatalf("want %d fdinfos, have %d", want, have)
	}
	for i, fd := range wantFDs {
		if want, have := fd, snap.FDInfos[i].FD; want != have {
			t.Errorf("want fd %q at index %d, have %q", want, i, have)
		}
	}
	if want, have := "144", snap.FDInfos[0].Ino; want != have {
		t.Errorf("want ino %q, have %q", want, have)
	}

	// Maps must be sorted by start address even though the fixture lists
	// them out of order.
	wantMaps := []struct {
		start    uintptr
		pathname string
	}{
		{0x55680ae1e000, "/bin/cat"},
		{0x55680ae29000, "/bin/cat"},
		{0x55680bed6000, "[heap]"},
		{0x7fdf973f2000, "/lib/x86_64-linux-gnu/libc-2.29.so"},
	}
	if want, have := len(wantMaps), len(snap.Maps); want != have {
		t.Fatalf("want %d maps, have %d", want, have)
	}
	for i, m := range wantMaps {
		if want, have := m.start, snap.Maps[i].StartAddr; want != have {
			t.Errorf("want start addr %#x at index %d, have %#x", want, i, have)
		}
		if want, have := m.pathname, snap.Maps[i].Pathname; want != have {
			t.Errorf("want pathname %q at index %d, have %q", want, i, have)
		}
	}

	// A second read of the same process must produce an identical snapshot.
	again, err := p.ResourceSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(snap, again); diff != "" {
		t.Fatalf("repeated snapshot differs (-first +second):\n%s", diff)
	}
}

func TestProcResourceSnapshotPartial(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26237)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := p.ResourceSnapshot(context.Background())
	if snap == nil {
		t.Fatal("want partial snapshot, have nil")
	}

	var partial *PartialSnapshotError
	if !errors.As(err, &partial) {
		t.Fatalf("want PartialSnapshotError, have %v", err)
	}

	// fd/1 has no fdinfo file: it vanished mid-read and must be indexed,
	// not fabricated.
	if diff := cmp.Diff([]string{"1"}, partial.MissingFDs); diff != "" {
		t.Errorf("unexpected missing fds (-want +got):\n%s", diff)
	}
	if want, have := 1, len(snap.FDInfos); want != have {
		t.Fatalf("want %d fdinfo, have %d", want, have)
	}
	if want, have := "0", snap.FDInfos[0].FD; want != have {
		t.Errorf("want fd %q, have %q", want, have)
	}

	// Line 1 of maps is unparseable: it must be indexed and skipped.
	if diff := cmp.Diff([]int{1}, partial.MissingMapLines); diff != "" {
		t.Errorf("unexpected missing maps lines (-want +got):\n%s", diff)
	}
	if want, have := 2, len(snap.Maps); want != have {
		t.Fatalf("want %d maps, have %d", want, have)
	}
}

func TestProcResourceSnapshotInvalidFDName(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26238)
	if err != nil {
		t.Fatal(err)
	}

	// fd/2x is not a plain fd number; the path escape must be rejected.
	snap, err := p.ResourceSnapshot(context.Background())
	if !errors.Is(err, ErrFileParse) {
		t.Fatalf("want ErrFileParse, have %v", err)
	}
	if snap != nil {
		t.Errorf("want nil snapshot, have %+v", snap)
	}
}

func TestProcResourceSnapshotCancel(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26236)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snap, err := p.ResourceSnapshot(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, have %v", err)
	}
	if snap != nil {
		t.Errorf("want nil snapshot, have %+v", snap)
	}
}

func TestVerifyProcessIdentity(t *testing.T) {
	if err := verifyProcessIdentity(26236, 90001, 90001); err != nil {
		t.Errorf("want no error for stable identity, have %v", err)
	}

	err := verifyProcessIdentity(26236, 90001, 90002)
	if !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("want ErrProcessChanged, have %v", err)
	}
}

// TestProcResourceSnapshotNoHandleLeak snapshots the test process itself
// repeatedly and verifies that no file descriptors are leaked.
func TestProcResourceSnapshotNoHandleLeak(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/self/fd")
	}

	fs, err := NewDefaultFS()
	if err != nil {
		t.Fatal(err)
	}
	p, err := fs.Self()
	if err != nil {
		t.Fatal(err)
	}

	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	before := countFDs()
	for i := 0; i < 50; i++ {
		_, err := p.ResourceSnapshot(context.Background())
		var partial *PartialSnapshotError
		if err != nil && !errors.As(err, &partial) {
			t.Fatal(err)
		}
	}
	if want, have := before, countFDs(); want != have {
		t.Errorf("want %d open fds after 50 snapshots, have %d", want, have)
	}
}
