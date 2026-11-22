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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// scriptedMountSource is a mountFileSource that serves a scripted sequence of
// raw file contents. Every read returns a private copy of the scripted bytes,
// mirroring the independent buffers and file descriptors of the real source.
type scriptedMountSource struct {
	mu          sync.Mutex
	infoReads   [][]byte
	statsReads  [][]byte
	calls       []string
	outstanding map[uintptr][]byte
}

func (s *scriptedMountSource) readMountInfoRaw() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "mountinfo")
	if len(s.infoReads) == 0 {
		return nil, fmt.Errorf("scripted mountinfo reads exhausted")
	}
	raw := bytes.Clone(s.infoReads[0])
	s.infoReads = s.infoReads[1:]
	s.track(raw)
	return raw, nil
}

func (s *scriptedMountSource) readMountStatsRaw() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "mountstats")
	if len(s.statsReads) == 0 {
		return nil, fmt.Errorf("scripted mountstats reads exhausted")
	}
	raw := bytes.Clone(s.statsReads[0])
	s.statsReads = s.statsReads[1:]
	s.track(raw)
	return raw, nil
}

// track retains every buffer handed out so tests can prove no buffer is ever
// reused between reads. The slices themselves are kept (not just their
// addresses) so the garbage collector cannot recycle a backing array.
func (s *scriptedMountSource) track(raw []byte) {
	if s.outstanding == nil {
		s.outstanding = map[uintptr][]byte{}
	}
	ptr := reflect.ValueOf(raw).Pointer()
	if _, seen := s.outstanding[ptr]; seen {
		panic(fmt.Sprintf("mount source reused buffer %#x across reads", ptr))
	}
	s.outstanding[ptr] = raw
}

func (s *scriptedMountSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// Stable, mutually consistent fixture contents.
const (
	snapshotMountInfoV1 = `21 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
22 21 8:2 / /mnt/data rw shared:2 - xfs /dev/sdb1 rw
23 21 0:43 / /mnt/nfs rw shared:3 - nfs4 192.168.1.1:/srv rw
`
	snapshotMountInfoV2 = `21 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
22 21 8:2 / /mnt/data rw shared:2 - xfs /dev/sdb1 rw
23 21 0:43 / /mnt/nfs rw shared:3 - nfs4 192.168.1.1:/srv rw
24 21 8:3 / /mnt/new rw shared:4 - btrfs /dev/sdc1 rw
`
	snapshotMountStatsOK = `device /dev/sda1 mounted on / with fstype ext4
device /dev/sdb1 mounted on /mnt/data with fstype xfs
device 192.168.1.1:/srv mounted on /mnt/nfs with fstype nfs4 statvers=1.0
	xprt:	tcp 1 2 3 4 5 6 7 8 9 10
`

	// snapshotMountStatsV2 matches snapshotMountInfoV2. The new mount appears
	// before the NFS entry because an NFS device block must remain last: its
	// per-operation section runs to EOF in this minimal fixture. Pairing is
	// mount-point based, so mountstats order need not match mountinfo order.
	snapshotMountStatsV2 = `device /dev/sda1 mounted on / with fstype ext4
device /dev/sdb1 mounted on /mnt/data with fstype xfs
device /dev/sdc1 mounted on /mnt/new with fstype btrfs
device 192.168.1.1:/srv mounted on /mnt/nfs with fstype nfs4 statvers=1.0
	xprt:	tcp 1 2 3 4 5 6 7 8 9 10
`
)

func stableSource() *scriptedMountSource {
	return &scriptedMountSource{
		infoReads:  [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV1)},
		statsReads: [][]byte{[]byte(snapshotMountStatsOK)},
	}
}

func TestMountSnapshotHappyPath(t *testing.T) {
	source := stableSource()
	snapshot, err := readMountSnapshot(source)
	if err != nil {
		t.Fatalf("readMountSnapshot: %v", err)
	}

	if got, want := len(snapshot.MountInfo()), 3; got != want {
		t.Fatalf("MountInfo length: got %d, want %d", got, want)
	}
	if got, want := len(snapshot.MountStats()), 3; got != want {
		t.Fatalf("MountStats length: got %d, want %d", got, want)
	}
	if got, want := len(snapshot.Views()), 3; got != want {
		t.Fatalf("Views length: got %d, want %d", got, want)
	}
	if snapshot.Generation() == "" {
		t.Fatal("generation token must not be empty")
	}

	// Each view pairs the mountinfo entry with its matching mountstats entry,
	// and NFS statistics survive the pairing.
	views := snapshot.Views()
	want := []MountView{
		{Info: snapshot.MountInfo()[0], Stats: snapshot.MountStats()[0]},
		{Info: snapshot.MountInfo()[1], Stats: snapshot.MountStats()[1]},
		{Info: snapshot.MountInfo()[2], Stats: snapshot.MountStats()[2]},
	}
	if diff := cmp.Diff(want, views); diff != "" {
		t.Fatalf("unexpected views (-want +got):\n%s", diff)
	}

	// Every committed view carries a mountstats entry; only the embedded
	// MountStats interface is nil for a filesystem without per-mount stats.
	for i, view := range views {
		if view.Info == nil || view.Stats == nil {
			t.Fatalf("view %d has a nil half: %+v", i, view)
		}
	}
	if views[0].Stats.Stats != nil {
		t.Fatalf("ext4 mount must have a nil embedded MountStats, got %T", views[0].Stats.Stats)
	}
	nfs, ok := views[2].Stats.Stats.(*MountStatsNFS)
	if !ok {
		t.Fatalf("expected NFS stats, got %T", views[2].Stats.Stats)
	}
	if nfs.StatVersion != "1.0" || len(nfs.Transport) != 1 {
		t.Fatalf("unexpected NFS stats: %+v", nfs)
	}

	// A logical read is exactly: mountinfo, mountstats, mountinfo.
	if diff := cmp.Diff([]string{"mountinfo", "mountstats", "mountinfo"}, source.calls); diff != "" {
		t.Fatalf("unexpected read sequence (-want +got):\n%s", diff)
	}
}

func TestMountSnapshotGenerationIsContentAddressed(t *testing.T) {
	g1 := mountGeneration([]byte(snapshotMountInfoV1))
	g2 := mountGeneration([]byte(snapshotMountInfoV1))
	g3 := mountGeneration([]byte(snapshotMountInfoV2))
	if g1 != g2 {
		t.Fatalf("identical content produced different generations: %q vs %q", g1, g2)
	}
	if g1 == g3 {
		t.Fatal("different content produced the same generation token")
	}
}

func TestMountSnapshotGenerationChangeRetriesAndCommits(t *testing.T) {
	// First attempt sees V1 then V2 (generation change); the retry sees a
	// stable V2 throughout and must commit that generation.
	source := &scriptedMountSource{
		infoReads: [][]byte{
			[]byte(snapshotMountInfoV1), // attempt 1, first read
			[]byte(snapshotMountInfoV2), // attempt 1, second read -> conflict
			[]byte(snapshotMountInfoV2), // attempt 2, first read
			[]byte(snapshotMountInfoV2), // attempt 2, second read -> stable
		},
		// Both attempts consume a mountstats read. The retry's cross-check
		// requires a stats set matching the V2 generation, including the new
		// mount; the first attempt never reaches cross-check anyway.
		statsReads: [][]byte{
			[]byte(snapshotMountStatsV2),
			[]byte(snapshotMountStatsV2),
		},
	}

	snapshot, err := readMountSnapshot(source)
	if err != nil {
		t.Fatalf("expected retry to recover from generation change, got %v", err)
	}
	if got, want := len(snapshot.MountInfo()), 4; got != want {
		t.Fatalf("committed snapshot has %d mounts, want %d", got, want)
	}
	if snapshot.Generation() != mountGeneration([]byte(snapshotMountInfoV2)) {
		t.Fatal("snapshot committed the wrong generation after retry")
	}
	if diff := cmp.Diff(
		[]string{"mountinfo", "mountstats", "mountinfo", "mountinfo", "mountstats", "mountinfo"},
		source.calls); diff != "" {
		t.Fatalf("unexpected read sequence (-want +got):\n%s", diff)
	}
}

func TestMountSnapshotGenerationChangeFatalWithZeroRetries(t *testing.T) {
	source := &scriptedMountSource{
		infoReads:  [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV2)},
		statsReads: [][]byte{[]byte(snapshotMountStatsOK)},
	}

	reader := newMountSnapshotReader(source, []MountSnapshotOption{WithMountSnapshotRetries(0)})
	_, err := reader.read()
	if !errors.Is(err, ErrMountGenerationChanged) {
		t.Fatalf("want ErrMountGenerationChanged, got %v", err)
	}

	// The failed transition must roll back to the idle state with no scratch
	// data retained, so a later attempt cannot mix old statistics.
	if reader.state != stateIdle {
		t.Fatalf("reader state = %d, want stateIdle", reader.state)
	}
	if reader.firstInfoRaw != nil || reader.secondInfoRaw != nil || reader.statsRaw != nil {
		t.Fatal("rolled-back reader still buffers data from the failed attempt")
	}
}

func TestMountSnapshotRetriesExhaustedReturnsLastConflict(t *testing.T) {
	source := &scriptedMountSource{
		infoReads: [][]byte{
			[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV2),
			[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV2),
		},
		statsReads: [][]byte{[]byte(snapshotMountStatsOK), []byte(snapshotMountStatsOK)},
	}

	_, err := readMountSnapshot(source, WithMountSnapshotRetries(1))
	if !errors.Is(err, ErrMountGenerationChanged) {
		t.Fatalf("want ErrMountGenerationChanged after exhausting retries, got %v", err)
	}
}

func TestMountSnapshotMountDisappeared(t *testing.T) {
	// mountinfo keeps /mnt/data, but mountstats no longer lists it: the mount
	// was unmounted between the two file reads. The snapshot must refuse rather
	// than silently dropping the mount or pairing it with stale statistics.
	stats := "device /dev/sda1 mounted on / with fstype ext4\n" +
		"device 192.168.1.1:/srv mounted on /mnt/nfs with fstype nfs4 statvers=1.0\n" +
		"\txprt:\ttcp 1 2 3 4 5 6 7 8 9 10\n"
	source := &scriptedMountSource{
		infoReads:  [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV1)},
		statsReads: [][]byte{[]byte(stats)},
	}

	_, err := readMountSnapshot(source)
	if !errors.Is(err, ErrMountDisappeared) {
		t.Fatalf("want ErrMountDisappeared, got %v", err)
	}
}

func TestMountSnapshotDeviceReplaced(t *testing.T) {
	// Same mount point, but a different device now backs it.
	stats := strings.Replace(snapshotMountStatsOK,
		"device /dev/sdb1 mounted on /mnt/data with fstype xfs",
		"device /dev/sdc9 mounted on /mnt/data with fstype ext4", 1)
	source := &scriptedMountSource{
		infoReads:  [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV1)},
		statsReads: [][]byte{[]byte(stats)},
	}

	_, err := readMountSnapshot(source)
	if !errors.Is(err, ErrMountDeviceReplaced) {
		t.Fatalf("want ErrMountDeviceReplaced, got %v", err)
	}
}

func TestMountSnapshotTruncatedFiles(t *testing.T) {
	tests := []struct {
		name      string
		infoReads [][]byte
		stats     []byte
	}{
		{
			name:      "truncated mountinfo",
			infoReads: [][]byte{[]byte("21 0 8:1 / / rw - ext4\n"), []byte(snapshotMountInfoV1)},
			stats:     []byte(snapshotMountStatsOK),
		},
		{
			name:      "truncated mountstats",
			infoReads: [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV1)},
			stats:     []byte("device truncated\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &scriptedMountSource{
				infoReads:  tt.infoReads,
				statsReads: [][]byte{tt.stats},
			}
			_, err := readMountSnapshot(source, WithMountSnapshotRetries(0))
			if !errors.Is(err, ErrMountSnapshotTruncated) {
				t.Fatalf("want ErrMountSnapshotTruncated, got %v", err)
			}
			// The underlying parse failure must remain identifiable too.
			if !errors.Is(err, ErrFileParse) {
				t.Fatalf("error %v no longer wraps ErrFileParse", err)
			}
		})
	}
}

func TestMountSnapshotFilterRunsAfterCapture(t *testing.T) {
	source := stableSource()
	snapshot, err := readMountSnapshot(source)
	if err != nil {
		t.Fatalf("readMountSnapshot: %v", err)
	}
	fullReads := source.callCount()

	// Filtering operates on the committed snapshot and never re-opens files,
	// so it cannot change the traversal scope of the capture.
	filtered := snapshot.Filtered(MountFilterDevices("/dev/sdb1"))
	if got, want := len(filtered), 1; got != want {
		t.Fatalf("filtered views: got %d, want %d", got, want)
	}
	if filtered[0].Info.Source != "/dev/sdb1" {
		t.Fatalf("unexpected filtered mount: %+v", filtered[0])
	}
	if source.callCount() != fullReads {
		t.Fatal("filtering triggered additional file reads")
	}
	if got := len(snapshot.Views()); got != 3 {
		t.Fatalf("filter mutated the snapshot's full view: now %d entries", got)
	}

	// A nil filter is treated as "keep everything".
	if got := len(snapshot.Filtered(nil)); got != 3 {
		t.Fatalf("nil filter kept %d entries, want 3", got)
	}
}

func TestMountFilterDevices(t *testing.T) {
	keep := MountFilterDevices("dev-a", "dev-b")
	if keep(nil) {
		t.Fatal("filter must reject nil MountInfo")
	}
	if !keep(&MountInfo{Source: "dev-b"}) {
		t.Fatal("filter rejected a listed device")
	}
	if keep(&MountInfo{Source: "dev-c"}) {
		t.Fatal("filter accepted an unlisted device")
	}
}

func TestMountSnapshotConcurrentReadsUseIndependentBuffers(t *testing.T) {
	source := &scriptedMountSource{
		infoReads:  nil, // populated below
		statsReads: nil,
	}
	// Enough scripted reads for every goroutine to attempt a full capture.
	const goroutines = 50
	for range goroutines {
		source.infoReads = append(source.infoReads,
			[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV1))
		source.statsReads = append(source.statsReads, []byte(snapshotMountStatsOK))
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, err := readMountSnapshot(source)
			if err != nil {
				errs <- err
				return
			}
			if len(snapshot.Views()) != 3 {
				errs <- fmt.Errorf("got %d views, want 3", len(snapshot.Views()))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestMountSnapshotRealFilesAndIndependentBuffers(t *testing.T) {
	dir := t.TempDir()
	infoPath := filepath.Join(dir, "mountinfo")
	statsPath := filepath.Join(dir, "mountstats")
	if err := os.WriteFile(infoPath, []byte(snapshotMountInfoV1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statsPath, []byte(snapshotMountStatsOK), 0o644); err != nil {
		t.Fatal(err)
	}

	source := procMountFileSource{mountInfoPath: infoPath, mountStatsPath: statsPath}
	snapshot, err := readMountSnapshot(source)
	if err != nil {
		t.Fatalf("readMountSnapshot: %v", err)
	}
	if len(snapshot.Views()) != 3 {
		t.Fatalf("got %d views, want 3", len(snapshot.Views()))
	}

	// Repeated opens return independent buffers: mutating one must not affect
	// the next read, and there is no shared mount cache to corrupt.
	first, err := readProcFileFull(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readProcFileFull(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || &first[0] == &second[0] {
		t.Fatal("expected distinct backing arrays for independent reads")
	}
	first[0] = 'X'
	if second[0] == 'X' {
		t.Fatal("reads share a buffer: mutating one read corrupted another")
	}
}

func TestReadProcFileFullReadsBeyondOneMiB(t *testing.T) {
	var b strings.Builder
	const n = 20000
	for i := range n {
		fmt.Fprintf(&b, "%d 35 98:0 /mnt%d /mnt%d rw,noatime shared:1 - ext3 /dev/root rw\n", i, i, i)
	}
	content := b.String()

	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := readProcFileFull(path)
	if err != nil {
		t.Fatalf("readProcFileFull: %v", err)
	}
	if len(data) != len(content) {
		t.Fatalf("read capped at %d bytes, want %d", len(data), len(content))
	}
}

// TestMountSnapshotRejectsInconsistentFixture uses the shipped fixtures, whose
// mountinfo and mountstats describe different mount sets, to prove the
// recovery chain refuses to mix the two instead of returning partial data.
func TestMountSnapshotRejectsInconsistentFixture(t *testing.T) {
	proc, err := getProcFixtures(t).Proc(26231)
	if err != nil {
		t.Fatal(err)
	}
	_, err = proc.MountSnapshot()
	if !errors.Is(err, ErrMountDisappeared) && !errors.Is(err, ErrMountDeviceReplaced) {
		t.Fatalf("want a recognizable snapshot conflict error, got %v", err)
	}

	// The legacy, separate APIs remain available and unchanged in behaviour.
	if _, err := proc.MountInfo(); err != nil {
		t.Fatalf("Proc.MountInfo compatibility: %v", err)
	}
	if _, err := proc.MountStats(); err != nil {
		t.Fatalf("Proc.MountStats compatibility: %v", err)
	}
}

func TestMountInfoEqual(t *testing.T) {
	info, err := parseMountInfo([]byte(snapshotMountInfoV1))
	if err != nil {
		t.Fatal(err)
	}
	same, err := parseMountInfo([]byte(snapshotMountInfoV1))
	if err != nil {
		t.Fatal(err)
	}
	other, err := parseMountInfo([]byte(snapshotMountInfoV2))
	if err != nil {
		t.Fatal(err)
	}
	if !mountInfoEqual(info, same) {
		t.Fatal("identical mountinfo views compared unequal")
	}
	if mountInfoEqual(info, other) {
		t.Fatal("different mountinfo generations compared equal")
	}
	if mountInfoEqual(info, info[:2]) {
		t.Fatal("views of different length compared equal")
	}
}

// TestMountSnapshotFSEntryPoints exercises every exported snapshot entry point
// against a small, on-disk fake proc filesystem so the path construction for
// /proc/self and /proc/<pid> is verified end to end.
func TestMountSnapshotFSEntryPoints(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"self", "4242"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "mountinfo"),
			[]byte(snapshotMountInfoV1), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "mountstats"),
			[]byte(snapshotMountStatsOK), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fs, err := NewFS(root)
	if err != nil {
		t.Fatal(err)
	}

	selfSnapshot, err := fs.GetMountSnapshot()
	if err != nil {
		t.Fatalf("FS.GetMountSnapshot: %v", err)
	}
	if len(selfSnapshot.Views()) != 3 {
		t.Fatalf("self snapshot: got %d views, want 3", len(selfSnapshot.Views()))
	}

	procSnapshot, err := fs.GetProcMountSnapshot(4242)
	if err != nil {
		t.Fatalf("FS.GetProcMountSnapshot: %v", err)
	}
	if diff := cmp.Diff(selfSnapshot.Views(), procSnapshot.Views()); diff != "" {
		t.Fatalf("self and pid snapshots differ (-want +got):\n%s", diff)
	}
	if selfSnapshot.Generation() != procSnapshot.Generation() {
		t.Fatal("identical content produced different generation tokens")
	}

	proc, err := fs.Proc(4242)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proc.MountSnapshot(); err != nil {
		t.Fatalf("Proc.MountSnapshot: %v", err)
	}

	// A missing mountstats file is reported through the normal open error path.
	if err := os.Remove(filepath.Join(root, "4242", "mountstats")); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.GetProcMountSnapshot(4242); err == nil {
		t.Fatal("expected an error when mountstats is absent")
	}
}

func TestMountSnapshotReaderRollback(t *testing.T) {
	source := &scriptedMountSource{
		infoReads:  [][]byte{[]byte(snapshotMountInfoV1), []byte(snapshotMountInfoV2)},
		statsReads: [][]byte{[]byte(snapshotMountStatsOK)},
	}
	reader := newMountSnapshotReader(source, []MountSnapshotOption{WithMountSnapshotRetries(0)})
	if reader.state != stateIdle {
		t.Fatalf("initial state = %d, want stateIdle", reader.state)
	}
	if _, err := reader.read(); err == nil {
		t.Fatal("expected a generation conflict")
	}
	if reader.state != stateIdle {
		t.Fatalf("post-failure state = %d, want stateIdle", reader.state)
	}
	if reader.firstInfoRaw != nil || reader.secondInfoRaw != nil || reader.statsRaw != nil {
		t.Fatal("rollback did not release the attempt's buffers")
	}
}
