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
	"maps"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/procfs/internal/parsers"
)

var (
	// ErrProcIdentityChanged is returned when the identity of a process
	// (PID, start time and namespace membership) changes while a snapshot
	// is being read, e.g. because the process exited and its PID was
	// reused by an unrelated process. No partial, mixed-process data is
	// returned in that case.
	ErrProcIdentityChanged = errors.New("process identity changed during snapshot")
	// ErrProcGone is returned when a process exits while a snapshot is
	// being read and its /proc entries disappear mid-read.
	ErrProcGone = errors.New("process exited during snapshot")
)

// snapshotMaxAttempts bounds how often a snapshot read is restarted when
// the process disappears mid-read. Permission and identity-change
// failures are terminal and are never retried.
const snapshotMaxAttempts = 3

// ProcIdentity uniquely identifies one instance of a process. Two
// processes may share the same PID only at different times, so the start
// time (clock ticks since boot, from /proc/<pid>/stat) and the namespace
// membership together pin down a single process instance.
type ProcIdentity struct {
	// The process ID.
	PID int
	// The time the process started after system boot, in clock ticks.
	StartTime uint64
	// The namespaces the process is a member of. Two processes in the
	// same namespace share the same namespace inode.
	Namespaces Namespaces
}

// Equal reports whether two identities refer to the same process instance.
func (id ProcIdentity) Equal(other ProcIdentity) bool {
	return id.PID == other.PID &&
		id.StartTime == other.StartTime &&
		maps.Equal(id.Namespaces, other.Namespaces)
}

// ProcSnapshot is a consistent, read-only view of a process's stat,
// status and file descriptor information. The identity of the process is
// verified before and after the underlying files are read, so every
// accessor is guaranteed to describe the same process instance.
//
// A ProcSnapshot is immutable after construction and safe for concurrent
// use by multiple goroutines. It holds no locks and keeps no files open,
// so sharing it never blocks the process from exiting.
type ProcSnapshot struct {
	identity ProcIdentity
	fs       FS
	stat     []byte
	status   []byte
	fds      []string
}

// Snapshot captures a consistent snapshot of the process's stat, status
// and file descriptor information.
//
// If the process exits and its PID is reused while the snapshot is being
// read, the identity check fails and ErrProcIdentityChanged is returned
// instead of partial data mixed from two processes. If the process exits
// mid-read without reuse, ErrProcGone is returned; this transient state
// is retried up to a fixed number of times before giving up. Permission
// failures are returned wrapping os.ErrPermission and are not retried.
func (p Proc) Snapshot() (*ProcSnapshot, error) {
	var err error
	for attempt := 0; attempt < snapshotMaxAttempts; attempt++ {
		var snap *ProcSnapshot
		snap, err = p.snapshot()
		if err == nil || !errors.Is(err, ErrProcGone) {
			return snap, err
		}
	}
	return nil, err
}

// snapshot reads the process files once, bracketed by identity checks.
func (p Proc) snapshot() (*ProcSnapshot, error) {
	before, err := p.identity()
	if err != nil {
		return nil, err
	}

	stat, err := readSnapshotFile(p.path("stat"))
	if err != nil {
		return nil, err
	}
	status, err := readSnapshotFile(p.path("status"))
	if err != nil {
		return nil, err
	}
	fds, err := readSnapshotDir(p.path("fd"))
	if err != nil {
		return nil, err
	}

	after, err := p.identity()
	if err != nil {
		return nil, err
	}
	if !before.Equal(after) {
		return nil, fmt.Errorf("%w: pid %d (start time %d -> %d)",
			ErrProcIdentityChanged, p.PID, before.StartTime, after.StartTime)
	}

	return &ProcSnapshot{identity: before, fs: p.fs, stat: stat, status: status, fds: fds}, nil
}

// identity reads the current identity of the process.
func (p Proc) identity() (ProcIdentity, error) {
	id := ProcIdentity{PID: p.PID}

	data, err := readSnapshotFile(p.path("stat"))
	if err != nil {
		return id, err
	}
	start, err := statStartTime(data)
	if err != nil {
		return id, err
	}
	id.StartTime = start

	// Namespace membership is part of the identity. If the kernel (or a
	// fixture) does not expose /proc/<pid>/ns, fall back to the PID and
	// start time alone.
	ns, err := p.Namespaces()
	switch {
	case err == nil:
		id.Namespaces = ns
	case errors.Is(err, os.ErrNotExist):
	default:
		return id, err
	}

	return id, nil
}

// Identity returns the verified identity of the process at snapshot time.
func (s *ProcSnapshot) Identity() ProcIdentity {
	return s.identity
}

// Stat returns the status information of the process as of snapshot time,
// parsed like Proc.Stat.
func (s *ProcSnapshot) Stat() (ProcStat, error) {
	return parseProcStat(s.stat, s.identity.PID, s.fs)
}

// Status returns the status information of the process as of snapshot
// time, parsed like Proc.NewStatus.
func (s *ProcSnapshot) Status() (ProcStatus, error) {
	return parseProcStatus(s.status, s.identity.PID)
}

// FileDescriptors returns the open file descriptors of the process as of
// snapshot time, parsed like Proc.FileDescriptors.
func (s *ProcSnapshot) FileDescriptors() ([]uintptr, error) {
	fds := make([]uintptr, len(s.fds))
	for i, n := range s.fds {
		fd, err := strconv.ParseInt(n, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: Cannot parse line: %v: %w", ErrFileParse, i, err)
		}
		fds[i] = uintptr(fd)
	}

	return fds, nil
}

// FileDescriptorsLen returns the number of open file descriptors of the
// process as of snapshot time.
func (s *ProcSnapshot) FileDescriptorsLen() int {
	return len(s.fds)
}

// readSnapshotFile reads a single proc file of a process, classifying
// failures into the snapshot terminal states.
func readSnapshotFile(path string) ([]byte, error) {
	data, err := parsers.ReadFileNoStat(path)
	if err != nil {
		return nil, snapshotErr(path, err)
	}
	return data, nil
}

// readSnapshotDir lists a proc directory of a process, classifying
// failures into the snapshot terminal states.
func readSnapshotDir(path string) ([]string, error) {
	d, err := os.Open(path)
	if err != nil {
		return nil, snapshotErr(path, err)
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("%w: Cannot read file: %v: %w", ErrFileRead, names, err)
	}

	return names, nil
}

// snapshotErr maps read failures onto the snapshot terminal states: a
// vanished process (ErrProcGone, retried a bounded number of times) and
// permission failures (wrapping os.ErrPermission, never retried), so
// callers can tell the two apart with errors.Is.
func snapshotErr(path string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %s", ErrProcGone, path)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot read %s: %w", path, err)
	default:
		return err
	}
}

// statStartTime extracts the process start time (field 22, clock ticks
// since boot) from raw /proc/<pid>/stat contents.
func statStartTime(data []byte) (uint64, error) {
	r := bytes.LastIndex(data, []byte(")"))
	if r < 0 {
		return 0, fmt.Errorf("%w: unexpected format, couldn't extract comm %q", ErrFileParse, data)
	}

	// The first field after the comm is state (field 3), so the start
	// time (field 22) sits at index 19 of the remaining fields.
	fields := strings.Fields(string(data[r+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("%w: too few fields in stat %q", ErrFileParse, data)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: start time %q: %w", ErrFileParse, fields[19], err)
	}

	return start, nil
}
