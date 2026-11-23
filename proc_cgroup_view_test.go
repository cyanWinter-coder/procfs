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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// mixedCgroupData is a /proc/<pid>/cgroup snapshot from a mixed v1/v2
// (hybrid) system.
const mixedCgroupData = `10:rdma:/
9:memory:/user.slice/user-1000.slice
8:blkio:/user.slice
3:cpu,cpuacct:/user.slice/user-1000.slice/session-10.scope
0::/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service
`

func TestParseCgroupView(t *testing.T) {
	view, err := parseCgroupView(26231, []byte(mixedCgroupData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &CgroupView{
		PID: 26231,
		Entries: []Cgroup{
			{HierarchyID: 10, Controllers: []string{"rdma"}, Path: "/"},
			{HierarchyID: 9, Controllers: []string{"memory"}, Path: "/user.slice/user-1000.slice"},
			{HierarchyID: 8, Controllers: []string{"blkio"}, Path: "/user.slice"},
			{HierarchyID: 3, Controllers: []string{"cpu", "cpuacct"}, Path: "/user.slice/user-1000.slice/session-10.scope"},
			{HierarchyID: 0, Controllers: nil, Path: "/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service"},
		},
	}
	if diff := cmp.Diff(want, view, cmp.AllowUnexported(CgroupView{})); diff != "" {
		t.Fatalf("unexpected diff (-want +got):\n%s", diff)
	}

	// The full path of every entry must be preserved; it must never be
	// reduced to its last segment.
	for _, e := range view.Entries {
		if strings.Count(e.Path, "/") > 1 && filepath.Base(e.Path) == strings.TrimPrefix(e.Path, "/") {
			t.Errorf("path %q was reduced to its last segment", e.Path)
		}
	}
}

func TestCgroupVersion(t *testing.T) {
	tests := []struct {
		name   string
		cgroup Cgroup
		want   int
	}{
		{"v1 single controller", Cgroup{HierarchyID: 10, Controllers: []string{"rdma"}, Path: "/"}, 1},
		{"v1 co-mounted controllers", Cgroup{HierarchyID: 3, Controllers: []string{"cpu", "cpuacct"}, Path: "/a"}, 1},
		{"v2 unified hierarchy", Cgroup{HierarchyID: 0, Path: "/a/b"}, 2},
	}
	for _, test := range tests {
		if got := test.cgroup.Version(); got != test.want {
			t.Errorf("%s: got version %d, want %d", test.name, got, test.want)
		}
	}
}

func TestCgroupViewEntry(t *testing.T) {
	view, err := parseCgroupView(26231, []byte(mixedCgroupData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name       string
		controller string
		want       Cgroup
		wantErr    error
	}{
		{
			name:       "v1 co-mounted controller",
			controller: "cpu",
			want:       Cgroup{HierarchyID: 3, Controllers: []string{"cpu", "cpuacct"}, Path: "/user.slice/user-1000.slice/session-10.scope"},
		},
		{
			name:       "v1 controller at hierarchy root",
			controller: "rdma",
			want:       Cgroup{HierarchyID: 10, Controllers: []string{"rdma"}, Path: "/"},
		},
		{
			name:       "v2 controller resolves to unified hierarchy",
			controller: "io",
			want:       Cgroup{HierarchyID: 0, Path: "/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service"},
		},
		{
			name:       "v1-only controller absent from view",
			controller: "net_cls",
			wantErr:    ErrControllerUnsupported,
		},
		{
			name:       "unknown controller",
			controller: "bogus",
			wantErr:    ErrControllerUnsupported,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := view.Entry(test.controller)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got error %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

// testMounts models a hybrid mount table: v1 cpu,cpuacct and memory mounts
// plus the unified v2 mount.
func testMounts() []*MountInfo {
	return []*MountInfo{
		{
			FSType:       "cgroup",
			MountPoint:   "/sys/fs/cgroup/cpu,cpuacct",
			SuperOptions: map[string]string{"rw": "", "cpu": "", "cpuacct": ""},
		},
		{
			FSType:       "cgroup",
			MountPoint:   "/sys/fs/cgroup/memory",
			SuperOptions: map[string]string{"rw": "", "memory": ""},
		},
		{
			FSType:       "cgroup2",
			MountPoint:   "/sys/fs/cgroup/unified",
			SuperOptions: map[string]string{"rw": "", "nsdelegate": ""},
		},
	}
}

func TestCgroupViewStatPath(t *testing.T) {
	view, err := parseCgroupView(26231, []byte(mixedCgroupData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name       string
		controller string
		file       string
		want       string
		wantErr    error
	}{
		{
			name:       "v1 cpu stat keeps full path",
			controller: "cpu",
			file:       "cpu.stat",
			want:       "/sys/fs/cgroup/cpu,cpuacct/user.slice/user-1000.slice/session-10.scope/cpu.stat",
		},
		{
			name:       "v2 memory stat keeps full path",
			controller: "memory",
			file:       "memory.current",
			want:       "/sys/fs/cgroup/memory/user.slice/user-1000.slice/memory.current",
		},
		{
			name:       "v2-only controller uses unified mount",
			controller: "io",
			file:       "io.stat",
			want:       "/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service/io.stat",
		},
		{
			name:       "unknown controller is unsupported",
			controller: "bogus",
			file:       "bogus.stat",
			wantErr:    ErrControllerUnsupported,
		},
		{
			name:       "controller without hierarchy in view is unsupported",
			controller: "net_cls",
			file:       "net_cls.classid",
			wantErr:    ErrControllerUnsupported,
		},
		{
			name:       "controller without matching mount",
			controller: "blkio",
			file:       "blkio.weight",
			wantErr:    ErrMountPoint,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := view.StatPath(testMounts(), test.controller, test.file)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got error %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestReadCgroupFile(t *testing.T) {
	alive := func() bool { return true }
	gone := func() bool { return false }

	tests := []struct {
		name      string
		read      func(calls *int) func(string) ([]byte, error)
		procAlive func() bool
		retries   int
		want      []byte
		wantErr   error
		wantCalls int
	}{
		{
			name: "success on first read",
			read: func(calls *int) func(string) ([]byte, error) {
				return func(string) ([]byte, error) {
					*calls++
					return []byte("usage_usec 42\n"), nil
				}
			},
			procAlive: alive,
			retries:   3,
			want:      []byte("usage_usec 42\n"),
			wantCalls: 1,
		},
		{
			name: "transient missing file then success",
			read: func(calls *int) func(string) ([]byte, error) {
				return func(string) ([]byte, error) {
					*calls++
					if *calls == 1 {
						return nil, os.ErrNotExist
					}
					return []byte("ok"), nil
				}
			},
			procAlive: alive,
			retries:   3,
			want:      []byte("ok"),
			wantCalls: 2,
		},
		{
			name: "migrated cgroup returns ErrCgroupMoved after retries",
			read: func(calls *int) func(string) ([]byte, error) {
				return func(string) ([]byte, error) {
					*calls++
					return nil, os.ErrNotExist
				}
			},
			procAlive: alive,
			retries:   2,
			wantErr:   ErrCgroupMoved,
			wantCalls: 3,
		},
		{
			name: "exited process returns ErrCgroupProcessGone immediately",
			read: func(calls *int) func(string) ([]byte, error) {
				return func(string) ([]byte, error) {
					*calls++
					return nil, os.ErrNotExist
				}
			},
			procAlive: gone,
			retries:   3,
			wantErr:   ErrCgroupProcessGone,
			wantCalls: 1,
		},
		{
			name: "non-missing read error is returned as-is",
			read: func(calls *int) func(string) ([]byte, error) {
				return func(string) ([]byte, error) {
					*calls++
					return nil, os.ErrPermission
				}
			},
			procAlive: alive,
			retries:   3,
			wantErr:   os.ErrPermission,
			wantCalls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			got, err := readCgroupFile("/x/cpu.stat", test.procAlive, test.retries, test.read(&calls))
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got error %v, want %v", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.want != nil && !cmp.Equal(test.want, got) {
				t.Errorf("got %q, want %q", got, test.want)
			}
			if calls != test.wantCalls {
				t.Errorf("got %d read calls, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestCgroupStatReaderReadFile(t *testing.T) {
	// Build a fake unified cgroup2 tree on disk.
	root := t.TempDir()
	dir := filepath.Join(root, "user.slice", "user-1000.slice")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	view := &CgroupView{
		PID:     26231,
		Entries: []Cgroup{{HierarchyID: 0, Path: "/user.slice/user-1000.slice"}},
	}
	mounts := []*MountInfo{{
		FSType:       "cgroup2",
		MountPoint:   root,
		SuperOptions: map[string]string{"rw": ""},
	}}
	reader := CgroupStatReader{View: view, Mounts: mounts, Retries: 1}

	data, err := reader.ReadFile("cpu", "cpu.stat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "usage_usec 42\n" {
		t.Errorf("got %q, want %q", data, "usage_usec 42\n")
	}

	// Unknown controller degrades to explicit unsupported.
	if _, err := reader.ReadFile("bogus", "cpu.stat"); !errors.Is(err, ErrControllerUnsupported) {
		t.Errorf("got error %v, want %v", err, ErrControllerUnsupported)
	}

	// Removing the tree simulates a migrated container: after retries the
	// result is deterministically ErrCgroupMoved.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFile("cpu", "cpu.stat"); !errors.Is(err, ErrCgroupMoved) {
		t.Errorf("got error %v, want %v", err, ErrCgroupMoved)
	}

	// A view whose process directory is gone reports ErrCgroupProcessGone.
	view.procPath = filepath.Join(t.TempDir(), "no-such-pid")
	if _, err := reader.ReadFile("cpu", "cpu.stat"); !errors.Is(err, ErrCgroupProcessGone) {
		t.Errorf("got error %v, want %v", err, ErrCgroupProcessGone)
	}
}

func TestFSCgroupStatReader(t *testing.T) {
	// Build a fake /proc tree with one process whose cgroup view and mount
	// table point at a fake unified cgroup2 tree.
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "26231")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/user.slice\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cgRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cgRoot, "user.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "user.slice", "memory.current"), []byte("1048576\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mountinfo := "30 24 0:26 / " + cgRoot + " rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n"
	if err := os.WriteFile(filepath.Join(pidDir, "mountinfo"), []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFS(procRoot)
	if err != nil {
		t.Fatalf("unexpected error creating FS: %v", err)
	}
	reader, err := fs.CgroupStatReader(26231)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reader.View.PID != 26231 {
		t.Errorf("got pid %d, want 26231", reader.View.PID)
	}
	data, err := reader.ReadFile("memory", "memory.current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "1048576\n" {
		t.Errorf("got %q, want %q", data, "1048576\n")
	}

	// Removing the process directory simulates process exit: the next read
	// of a missing file reports ErrCgroupProcessGone.
	if err := os.RemoveAll(pidDir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(cgRoot, "user.slice")); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFile("memory", "memory.current"); !errors.Is(err, ErrCgroupProcessGone) {
		t.Errorf("got error %v, want %v", err, ErrCgroupProcessGone)
	}
}
