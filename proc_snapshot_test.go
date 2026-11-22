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

package procfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestProcSnapshotFixture(t *testing.T) {
	fs := getProcFixtures(t)
	p, err := fs.Proc(26231)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	id := snap.Identity()
	if want, have := 26231, id.PID; want != have {
		t.Errorf("want identity PID %d, have %d", want, have)
	}
	if want, have := uint64(82375), id.StartTime; want != have {
		t.Errorf("want identity start time %d, have %d", want, have)
	}
	for name, inode := range map[string]uint32{"mnt": 4026531840, "net": 4026531993} {
		if want, have := inode, id.Namespaces[name].Inode; want != have {
			t.Errorf("want namespace %s inode %d, have %d", name, want, have)
		}
	}

	// The snapshot must agree with the existing single-file readers.
	wantStat, err := p.Stat()
	if err != nil {
		t.Fatal(err)
	}
	haveStat, err := snap.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wantStat, haveStat) {
		t.Errorf("stat mismatch:\nwant: %+v\nhave: %+v", wantStat, haveStat)
	}

	wantStatus, err := p.NewStatus()
	if err != nil {
		t.Fatal(err)
	}
	haveStatus, err := snap.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wantStatus, haveStatus) {
		t.Errorf("status mismatch:\nwant: %+v\nhave: %+v", wantStatus, haveStatus)
	}

	wantFDs, err := p.FileDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	haveFDs, err := snap.FileDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(wantFDs)
	slices.Sort(haveFDs)
	if !slices.Equal(wantFDs, haveFDs) {
		t.Errorf("want fds %v, have %v", wantFDs, haveFDs)
	}
	if want, have := len(wantFDs), snap.FileDescriptorsLen(); want != have {
		t.Errorf("want %d fds, have %d", want, have)
	}
}

func TestProcSnapshotGone(t *testing.T) {
	fs := getProcFixtures(t)
	p := Proc{PID: 99999, fs: fs}

	snap, err := p.Snapshot()
	if err == nil {
		t.Fatalf("want error for exited process, got snapshot %+v", snap)
	}
	if !errors.Is(err, ErrProcGone) {
		t.Errorf("want ErrProcGone, have %v", err)
	}
	// The gone state must be distinguishable from a permission failure.
	if errors.Is(err, os.ErrPermission) {
		t.Errorf("ErrProcGone must not match os.ErrPermission: %v", err)
	}
	if errors.Is(err, ErrProcIdentityChanged) {
		t.Errorf("ErrProcGone must not match ErrProcIdentityChanged: %v", err)
	}
}

func TestProcSnapshotPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	p := snapshotTestProc(t, 4321, 100)
	stat := filepath.Join(p.fs.proc.Path(), "4321", "stat")
	if err := os.Chmod(stat, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(stat, 0o644) })

	_, err := p.Snapshot()
	if err == nil {
		t.Fatal("want permission error, got nil")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("want os.ErrPermission, have %v", err)
	}
	// Permission failures are terminal, not the transient gone state.
	if errors.Is(err, ErrProcGone) {
		t.Errorf("permission failure must not match ErrProcGone: %v", err)
	}
}

func TestProcSnapshotIdentityChanged(t *testing.T) {
	p := snapshotTestProc(t, 4321, 100)
	stat := filepath.Join(p.fs.proc.Path(), "4321", "stat")

	// Simulate PID reuse: rewrite the stat file with a different start
	// time (a "new process") in a tight loop, so the identity check
	// bracketing the snapshot read observes the change.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tmp := stat + ".tmp"
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.WriteFile(tmp, snapshotStatLine(4321, uint64(100+i)), 0o644); err != nil {
				return
			}
			if err := os.Rename(tmp, stat); err != nil {
				return
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()

	var changed int
	for i := 0; i < 200 && changed == 0; i++ {
		snap, err := p.Snapshot()
		switch {
		case err == nil:
			// Both identity reads landed between two rewrites; the
			// snapshot is consistent and may legitimately succeed.
			if snap == nil {
				t.Fatal("nil snapshot with nil error")
			}
		case errors.Is(err, ErrProcIdentityChanged):
			changed++
			if snap != nil {
				t.Fatal("identity change must not deliver a partial snapshot")
			}
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if changed == 0 {
		t.Fatal("want at least one ErrProcIdentityChanged while the process was replaced")
	}
}

func TestProcSnapshotConcurrent(t *testing.T) {
	fs := getProcFixtures(t)
	p, err := fs.Proc(26231)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	// A snapshot is read-only and must be shareable without locks.
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := snap.Stat(); err != nil {
					t.Error(err)
				}
				if _, err := snap.Status(); err != nil {
					t.Error(err)
				}
				if _, err := snap.FileDescriptors(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestProcIdentityEqual(t *testing.T) {
	base := ProcIdentity{
		PID:       42,
		StartTime: 1000,
		Namespaces: Namespaces{
			"mnt": {Type: "mnt", Inode: 4026531840},
			"net": {Type: "net", Inode: 4026531993},
		},
	}

	for _, tc := range []struct {
		name  string
		other ProcIdentity
		want  bool
	}{
		{"identical", base, true},
		{"pid differs", ProcIdentity{PID: 43, StartTime: 1000, Namespaces: base.Namespaces}, false},
		{"start time differs", ProcIdentity{PID: 42, StartTime: 1001, Namespaces: base.Namespaces}, false},
		{"namespace inode differs", ProcIdentity{PID: 42, StartTime: 1000, Namespaces: Namespaces{
			"mnt": {Type: "mnt", Inode: 4026531841},
			"net": {Type: "net", Inode: 4026531993},
		}}, false},
		{"namespace missing", ProcIdentity{PID: 42, StartTime: 1000, Namespaces: Namespaces{
			"mnt": {Type: "mnt", Inode: 4026531840},
		}}, false},
		{"no namespaces", ProcIdentity{PID: 42, StartTime: 1000}, false},
	} {
		if have := base.Equal(tc.other); have != tc.want {
			t.Errorf("%s: want %v, have %v", tc.name, tc.want, have)
		}
	}
}

// snapshotTestProc creates a minimal fake proc filesystem with a single
// process whose stat file carries the given start time.
func snapshotTestProc(t *testing.T, pid int, startTime uint64) Proc {
	t.Helper()

	dir := t.TempDir()
	pidDir := filepath.Join(dir, strconv.Itoa(pid))
	for _, sub := range []string{"fd", "ns"} {
		if err := os.MkdirAll(filepath.Join(pidDir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), snapshotStatLine(pid, startTime), 0o644); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\ttest\nTgid:\t%d\nPid:\t%d\n", pid, pid)
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	return Proc{PID: pid, fs: fs}
}

// snapshotStatLine renders a /proc/<pid>/stat line whose start time
// (field 22) is startTime.
func snapshotStatLine(pid int, startTime uint64) []byte {
	fields := make([]string, 50)
	for i := range fields {
		fields[i] = "1"
	}
	fields[0] = "S"
	fields[19] = strconv.FormatUint(startTime, 10)
	return []byte(fmt.Sprintf("%d (test) %s\n", pid, strings.Join(fields, " ")))
}
