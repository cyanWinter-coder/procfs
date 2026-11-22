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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Errors returned by the mount snapshot recovery chain. Callers should use
// errors.Is rather than matching on message text.
var (
	// ErrMountGenerationChanged indicates that the mount table changed
	// between the two mountinfo reads that bracket a logical snapshot. The
	// mountstats captured in between cannot be proven to describe the same
	// mount generation, so no partial result is returned.
	ErrMountGenerationChanged = errors.New("mount table generation changed during snapshot")

	// ErrMountDisappeared indicates that a mount present in mountinfo has no
	// matching entry in mountstats, typically because it was unmounted while
	// the snapshot was being captured.
	ErrMountDisappeared = errors.New("mount disappeared during snapshot")

	// ErrMountDeviceReplaced indicates that a mount point is present in both
	// files but is backed by a different device or filesystem type, i.e. the
	// mount was replaced (unmount followed by a new mount) during the read.
	ErrMountDeviceReplaced = errors.New("mount device replaced during snapshot")

	// ErrMountSnapshotTruncated indicates that one of the backing files was
	// truncated or otherwise produced a partial, unparseable view while the
	// snapshot was being captured.
	ErrMountSnapshotTruncated = errors.New("mount snapshot truncated")
)

// MountFilter selects mounts from a committed MountSnapshot. Filters run after
// the full, unfiltered view has been captured and cross-validated, so they
// never narrow the file traversal or hide generation conflicts.
type MountFilter func(*MountInfo) bool

// MountFilterDevices returns a MountFilter that keeps only mounts whose
// backing device (MountInfo.Source) matches one of the given devices.
func MountFilterDevices(devices ...string) MountFilter {
	allowed := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		allowed[device] = struct{}{}
	}
	return func(info *MountInfo) bool {
		if info == nil {
			return false
		}
		_, ok := allowed[info.Source]
		return ok
	}
}

// MountView is one mount as seen in both mountinfo and mountstats at the same
// generation. Stats is never nil for a committed snapshot, but its embedded
// MountStats interface is nil for filesystems (e.g. plain local ones) that
// carry no per-mount statistics in mountstats.
type MountView struct {
	Info  *MountInfo
	Stats *Mount
}

// MountSnapshot is a logically consistent view of mountinfo and mountstats.
// Every entry is guaranteed to originate from the same mount table generation;
// a failed capture returns an error and no snapshot, so callers can never mix
// statistics from an older generation into a newer mount view.
//
// A MountSnapshot is read-only and safe for concurrent use.
type MountSnapshot struct {
	info       []*MountInfo
	stats      []*Mount
	views      []MountView
	generation string
}

// Generation returns an opaque token identifying the mount table generation
// captured by this snapshot. Two snapshots with equal generation tokens were
// built from byte-identical mountinfo content.
func (s MountSnapshot) Generation() string {
	return s.generation
}

// MountInfo returns the full, unfiltered mountinfo view of the snapshot.
func (s MountSnapshot) MountInfo() []*MountInfo {
	return s.info
}

// MountStats returns the full, unfiltered mountstats view of the snapshot.
func (s MountSnapshot) MountStats() []*Mount {
	return s.stats
}

// Views returns every mount paired across mountinfo and mountstats.
func (s MountSnapshot) Views() []MountView {
	return s.views
}

// Filtered returns the subset of Views() accepted by f. The snapshot itself is
// not modified; filtering happens after the stable view was captured.
func (s MountSnapshot) Filtered(f MountFilter) []MountView {
	if f == nil {
		return s.views
	}
	filtered := make([]MountView, 0, len(s.views))
	for _, view := range s.views {
		if f(view.Info) {
			filtered = append(filtered, view)
		}
	}
	return filtered
}

// MountSnapshotOption configures a mount snapshot read.
type MountSnapshotOption func(*mountSnapshotConfig)

type mountSnapshotConfig struct {
	// retries is the number of additional attempts after a generation change.
	retries int
}

// WithMountSnapshotRetries overrides the number of additional attempts made
// when the mount table changes while a snapshot is being captured. The default
// is two retries (three attempts in total); zero makes a changed generation
// fatal on the first mismatch.
func WithMountSnapshotRetries(retries int) MountSnapshotOption {
	return func(c *mountSnapshotConfig) {
		if retries >= 0 {
			c.retries = retries
		}
	}
}

// mountSnapshotStates names the stages of the rollback-able capture. Each
// attempt starts at stateFirstInfo and either reaches stateCommitted or rolls
// back to stateIdle on failure.
const (
	stateIdle = iota
	stateFirstInfo
	stateStats
	stateSecondInfo
	stateCrossCheck
	stateCommitted
)

// mountFileSource abstracts the raw file reads behind a snapshot. Every call
// opens the file afresh and returns a private byte buffer, which keeps
// concurrent and repeated reads from sharing a mount cache or scratch space.
type mountFileSource interface {
	readMountInfoRaw() ([]byte, error)
	readMountStatsRaw() ([]byte, error)
}

// procMountFileSource reads mountinfo and mountstats from a single proc
// directory (either /proc/self or /proc/<pid>).
type procMountFileSource struct {
	mountInfoPath  string
	mountStatsPath string
}

func (s procMountFileSource) readMountInfoRaw() ([]byte, error) {
	return readProcFileFull(s.mountInfoPath)
}

func (s procMountFileSource) readMountStatsRaw() ([]byte, error) {
	return readProcFileFull(s.mountStatsPath)
}

// readProcFileFull opens path independently and reads it without the 1 MiB
// cap used by parsers.ReadFileNoStat. The returned buffer is owned by the
// caller and never pooled or shared.
func readProcFileFull(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mountSnapshotReader is the state machine driving one logical read. All
// intermediate state lives on the reader and is discarded on rollback, so a
// failed attempt can never leak stale statistics into a later one.
type mountSnapshotReader struct {
	source mountFileSource
	config mountSnapshotConfig
	state  int

	firstInfoRaw  []byte
	secondInfoRaw []byte
	statsRaw      []byte
}

func newMountSnapshotReader(source mountFileSource, opts []MountSnapshotOption) *mountSnapshotReader {
	r := &mountSnapshotReader{
		source: source,
		config: mountSnapshotConfig{retries: 2},
	}
	for _, opt := range opts {
		opt(&r.config)
	}
	return r
}

// rollback returns the reader to stateIdle and drops every buffered byte from
// the failed attempt. Reads already handed to the kernel are unaffected; only
// the reader's own scratch state is cleared.
func (r *mountSnapshotReader) rollback() {
	r.state = stateIdle
	r.firstInfoRaw = nil
	r.secondInfoRaw = nil
	r.statsRaw = nil
}

// read runs the full recovery chain, retrying from a clean state whenever the
// mount generation changes underneath us.
func (r *mountSnapshotReader) read() (*MountSnapshot, error) {
	var lastErr error
	for attempt := 0; attempt <= r.config.retries; attempt++ {
		r.rollback()

		snapshot, err := r.attempt()
		if err == nil {
			return snapshot, nil
		}
		lastErr = err

		// Only a generation conflict is recoverable by re-reading. Missing
		// mounts, device replacement and truncation are reported immediately.
		if !errors.Is(err, ErrMountGenerationChanged) {
			return nil, err
		}
	}
	return nil, lastErr
}

// attempt performs a single state transition sequence.
func (r *mountSnapshotReader) attempt() (*MountSnapshot, error) {
	// Stage 1: capture the opening mountinfo generation.
	r.state = stateFirstInfo
	firstRaw, err := r.source.readMountInfoRaw()
	if err != nil {
		r.rollback()
		return nil, err
	}
	r.firstInfoRaw = firstRaw

	firstInfo, err := parseMountInfo(firstRaw)
	if err != nil {
		r.rollback()
		return nil, wrapTruncated(err)
	}
	firstGeneration := mountGeneration(firstRaw)

	// Stage 2: read mountstats against that generation. The read uses its own
	// file descriptor and buffer, so it never shares state with stage 1.
	r.state = stateStats
	statsRaw, err := r.source.readMountStatsRaw()
	if err != nil {
		r.rollback()
		return nil, err
	}
	r.statsRaw = statsRaw

	stats, err := parseMountStats(bytes.NewReader(statsRaw))
	if err != nil {
		r.rollback()
		return nil, wrapTruncated(err)
	}

	// Stage 3: re-read mountinfo to prove the generation held still.
	r.state = stateSecondInfo
	secondRaw, err := r.source.readMountInfoRaw()
	if err != nil {
		r.rollback()
		return nil, err
	}
	r.secondInfoRaw = secondRaw

	secondInfo, err := parseMountInfo(secondRaw)
	if err != nil {
		r.rollback()
		return nil, wrapTruncated(err)
	}

	// Stage 4: verify both mountinfo reads describe one generation.
	r.state = stateCrossCheck
	secondGeneration := mountGeneration(secondRaw)
	if firstGeneration != secondGeneration || !mountInfoEqual(firstInfo, secondInfo) {
		r.rollback()
		return nil, fmt.Errorf("%w: generation %s -> %s",
			ErrMountGenerationChanged, firstGeneration, secondGeneration)
	}

	views, err := pairMountViews(firstInfo, stats)
	if err != nil {
		r.rollback()
		return nil, err
	}

	r.state = stateCommitted
	return &MountSnapshot{
		info:       firstInfo,
		stats:      stats,
		views:      views,
		generation: firstGeneration,
	}, nil
}

// wrapTruncated marks parse failures as truncated snapshots while preserving
// the original parse error (and its ErrFileParse sentinel) for errors.Is.
func wrapTruncated(err error) error {
	return fmt.Errorf("%w: %w", ErrMountSnapshotTruncated, err)
}

// mountGeneration derives an opaque, content-addressed generation token from
// raw mountinfo bytes.
func mountGeneration(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// mountIdentity is the mount-table identity used to compare two generations.
// Option maps are deliberately excluded: option-only changes are not mount
// generations, and map contents are already covered indirectly by the raw byte
// hash comparison in the caller.
type mountIdentity struct {
	mountID    int
	parentID   int
	majorMinor string
	root       string
	mountPoint string
	fsType     string
	source     string
}

func mountIdentityOf(m *MountInfo) mountIdentity {
	return mountIdentity{
		mountID:    m.MountID,
		parentID:   m.ParentID,
		majorMinor: m.MajorMinorVer,
		root:       m.Root,
		mountPoint: m.MountPoint,
		fsType:     m.FSType,
		source:     m.Source,
	}
}

// mountInfoEqual reports whether two parsed mountinfo views describe the same
// set of mounts in the same order.
func mountInfoEqual(a, b []*MountInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if mountIdentityOf(a[i]) != mountIdentityOf(b[i]) {
			return false
		}
	}
	return true
}

// pairMountViews cross-validates mountinfo against mountstats and pairs entries
// that belong to the same mount. Every mountinfo entry must have a
// corresponding mountstats entry; otherwise the two files are from different
// generations and the snapshot is rejected rather than partially assembled.
func pairMountViews(info []*MountInfo, stats []*Mount) ([]MountView, error) {
	views := make([]MountView, 0, len(info))
	for _, mi := range info {
		ms := findMountStats(stats, mi)
		if ms == nil {
			// No entry shares the mount point: the mount itself is gone.
			return nil, fmt.Errorf("%w: mount point %q (device %q) absent from mountstats",
				ErrMountDisappeared, mi.MountPoint, mi.Source)
		}
		if ms.Device != mi.Source || ms.Type != mi.FSType {
			// The mount point survived but a different device/fs backs it,
			// i.e. an unmount/remount cycle happened mid-read.
			return nil, fmt.Errorf("%w: mount point %q changed from %q (%s) to %q (%s)",
				ErrMountDeviceReplaced, mi.MountPoint,
				mi.Source, mi.FSType, ms.Device, ms.Type)
		}
		views = append(views, MountView{Info: mi, Stats: ms})
	}
	return views, nil
}

// findMountStats locates the mountstats entry for a mountinfo entry by mount
// point. The mount point is matched first so that a device replacement at the
// same location is distinguishable from a mount that disappeared altogether;
// device and filesystem type are checked by the caller. A linear scan is used
// instead of a map keyed by mount point so overlapping bind mounts cannot
// silently overwrite each other.
func findMountStats(stats []*Mount, info *MountInfo) *Mount {
	for _, ms := range stats {
		if ms.Mount == info.MountPoint {
			return ms
		}
	}
	return nil
}

// readMountSnapshot builds a stable snapshot from the given file source,
// retrying generation conflicts according to the supplied options.
func readMountSnapshot(source mountFileSource, opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return newMountSnapshotReader(source, opts).read()
}

// GetMountSnapshot captures a consistent mountinfo/mountstats snapshot for the
// current process (/proc/self).
func GetMountSnapshot(opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return readMountSnapshot(procMountFileSource{
		mountInfoPath:  "/proc/self/mountinfo",
		mountStatsPath: "/proc/self/mountstats",
	}, opts...)
}

// GetProcMountSnapshot captures a consistent mountinfo/mountstats snapshot for
// the given process under /proc/<pid>.
func GetProcMountSnapshot(pid int, opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return readMountSnapshot(procMountFileSource{
		mountInfoPath:  fmt.Sprintf("/proc/%d/mountinfo", pid),
		mountStatsPath: fmt.Sprintf("/proc/%d/mountstats", pid),
	}, opts...)
}

// GetMountSnapshot captures a consistent mountinfo/mountstats snapshot from
// the proc filesystem rooted at fs.
func (fs FS) GetMountSnapshot(opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return readMountSnapshot(procMountFileSource{
		mountInfoPath:  fs.proc.Path("self/mountinfo"),
		mountStatsPath: fs.proc.Path("self/mountstats"),
	}, opts...)
}

// GetProcMountSnapshot captures a consistent mountinfo/mountstats snapshot for
// the given process within the proc filesystem rooted at fs.
func (fs FS) GetProcMountSnapshot(pid int, opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return readMountSnapshot(procMountFileSource{
		mountInfoPath:  fs.proc.Path(fmt.Sprintf("%d/mountinfo", pid)),
		mountStatsPath: fs.proc.Path(fmt.Sprintf("%d/mountstats", pid)),
	}, opts...)
}

// MountSnapshot captures a consistent mountinfo/mountstats snapshot for the
// process represented by p.
func (p Proc) MountSnapshot(opts ...MountSnapshotOption) (*MountSnapshot, error) {
	return readMountSnapshot(procMountFileSource{
		mountInfoPath:  p.path("mountinfo"),
		mountStatsPath: p.path("mountstats"),
	}, opts...)
}
