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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/prometheus/procfs/internal/parsers"
)

// ErrProcessChanged is returned when the process identity (its start time)
// changes while a joint resource snapshot is being assembled. This means the
// PID was recycled mid-read and the snapshot would mix state belonging to two
// different processes, so it is rejected as a whole.
var ErrProcessChanged = errors.New("process changed during snapshot")

// fdDirBatchSize bounds how many fd directory entries are read per
// Readdirnames call so that context cancellation is honored promptly while
// traversing /proc/[pid]/fd.
const fdDirBatchSize = 16

// ProcResourceSnapshot is a joint view of a process's file descriptors,
// memory mappings and resource limits, assembled by a single call to
// Proc.ResourceSnapshot. All file handles used to build it are released
// before it is returned; the snapshot itself holds no resources and needs no
// cleanup.
type ProcResourceSnapshot struct {
	// PID of the process the snapshot belongs to.
	PID int
	// StartTime is the process start time (clock ticks since boot, as read
	// from /proc/[pid]/stat). It is captured before and after the read and
	// the snapshot is rejected with ErrProcessChanged if it differs.
	StartTime uint64
	// Limits are the process's resource limits, as returned by Proc.Limits.
	Limits ProcLimits
	// FDInfos are the per-fd details, as returned by Proc.FDInfo, sorted
	// numerically by file descriptor number.
	FDInfos ProcFDInfos
	// Maps are the process memory mappings, as returned by Proc.ProcMaps,
	// sorted by (StartAddr, Dev, Inode).
	Maps []*ProcMap
}

// PartialSnapshotError reports entries that vanished or became unreadable
// while a ProcResourceSnapshot was being assembled. It is returned together
// with a non-nil snapshot holding everything that could be read; no entries
// are fabricated to fill the gaps. Use errors.As to inspect it:
//
//	snap, err := p.ResourceSnapshot(ctx)
//	var partial *procfs.PartialSnapshotError
//	if errors.As(err, &partial) {
//		// snap is still usable; partial indexes what is missing.
//	}
type PartialSnapshotError struct {
	// MissingFDs lists the file descriptor numbers (decimal strings) that
	// were present in /proc/[pid]/fd but whose fdinfo file vanished before
	// it could be read.
	MissingFDs []string
	// MissingMapLines lists the 0-based line offsets in /proc/[pid]/maps
	// whose entries could not be parsed and were skipped.
	MissingMapLines []int
}

// Error implements the error interface.
func (e *PartialSnapshotError) Error() string {
	return fmt.Sprintf("partial resource snapshot: %d fd(s) vanished, %d maps line(s) skipped",
		len(e.MissingFDs), len(e.MissingMapLines))
}

// empty reports whether nothing went missing.
func (e *PartialSnapshotError) empty() bool {
	return len(e.MissingFDs) == 0 && len(e.MissingMapLines) == 0
}

// ResourceSnapshot reads the process's limits, fdinfo and maps in a single
// pass and returns them as one consistently ordered ProcResourceSnapshot,
// so that fd leak investigations correlate file descriptors and memory
// mappings taken from the same read of the process.
//
// The process identity (PID start time) is verified before and after the
// read; if it changed, the PID was recycled and ErrProcessChanged is
// returned instead of a mixed snapshot.
//
// If an individual fd or maps entry disappears mid-read, the snapshot is
// still returned, together with a *PartialSnapshotError indexing the missing
// entries. Cancellation of ctx stops the directory traversal promptly and
// all file handles are released before the call returns.
func (p Proc) ResourceSnapshot(ctx context.Context) (*ProcResourceSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	before, err := p.Stat()
	if err != nil {
		return nil, err
	}

	snap := &ProcResourceSnapshot{
		PID:       p.PID,
		StartTime: before.Starttime,
	}
	partial := &PartialSnapshotError{}

	limits, err := p.Limits()
	if err != nil {
		return nil, err
	}
	snap.Limits = limits

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fdinfos, err := p.snapshotFDInfos(ctx, partial)
	if err != nil {
		return nil, err
	}
	snap.FDInfos = fdinfos

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	maps, err := p.snapshotMaps(ctx, partial)
	if err != nil {
		return nil, err
	}
	snap.Maps = maps

	after, err := p.Stat()
	if err != nil {
		return nil, err
	}
	if err := verifyProcessIdentity(p.PID, before.Starttime, after.Starttime); err != nil {
		return nil, err
	}

	if !partial.empty() {
		return snap, partial
	}

	return snap, nil
}

// verifyProcessIdentity compares the process start time captured before and
// after a snapshot read. A change means the PID was recycled mid-read.
func verifyProcessIdentity(pid int, before, after uint64) error {
	if before != after {
		return fmt.Errorf("%w: pid %d start time changed from %d to %d",
			ErrProcessChanged, pid, before, after)
	}
	return nil
}

// validFDName reports whether name is a plain decimal file descriptor number,
// rejecting anything that could escape the fd directory (".", "..", names
// containing separators) or that is not a number at all.
func validFDName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// snapshotFDInfos traverses /proc/[pid]/fd in bounded batches (so ctx
// cancellation is honored promptly) and reads the fdinfo of each entry.
// Entries whose fdinfo vanished mid-read are recorded in partial and skipped.
func (p Proc) snapshotFDInfos(ctx context.Context, partial *PartialSnapshotError) (ProcFDInfos, error) {
	d, err := os.Open(p.path("fd"))
	if err != nil {
		return nil, err
	}
	defer d.Close()

	fdinfos := ProcFDInfos{}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		names, err := d.Readdirnames(fdDirBatchSize)
		for _, n := range names {
			if !validFDName(n) {
				return nil, fmt.Errorf("%w: invalid file descriptor name %q in %q", ErrFileParse, n, d.Name())
			}

			data, err := parsers.ReadFileNoStat(p.path("fdinfo", n))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// The fd was closed between the directory listing
					// and the fdinfo read; index it and move on.
					partial.MissingFDs = append(partial.MissingFDs, n)
					continue
				}
				return nil, err
			}

			fdinfo, err := parseFDInfo(n, data)
			if err != nil {
				return nil, err
			}
			fdinfos = append(fdinfos, *fdinfo)
		}

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: cannot read directory %q: %w", ErrFileRead, d.Name(), err)
		}
	}

	// Sort numerically by fd number; the kernel listing order is not
	// guaranteed and a lexicographic sort would order "10" before "2".
	sort.SliceStable(fdinfos, func(i, j int) bool {
		fi, _ := strconv.Atoi(fdinfos[i].FD)
		fj, _ := strconv.Atoi(fdinfos[j].FD)
		return fi < fj
	})

	return fdinfos, nil
}

// snapshotMaps reads /proc/[pid]/maps line by line, honoring ctx
// cancellation between lines. Lines that fail to parse are recorded in
// partial and skipped rather than replaced with fabricated entries.
func (p Proc) snapshotMaps(ctx context.Context, partial *PartialSnapshotError) ([]*ProcMap, error) {
	file, err := os.Open(p.path("maps"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	maps := []*ProcMap{}
	scan := bufio.NewScanner(file)

	for line := 0; scan.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		m, err := parseProcMap(scan.Text())
		if err != nil {
			partial.MissingMapLines = append(partial.MissingMapLines, line)
			continue
		}
		maps = append(maps, m)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// The kernel already lists mappings in address order; make the ordering
	// explicit and stable on the (StartAddr, Dev, Inode) key so snapshots
	// are comparable regardless of how the read was chunked.
	sort.SliceStable(maps, func(i, j int) bool {
		if maps[i].StartAddr != maps[j].StartAddr {
			return maps[i].StartAddr < maps[j].StartAddr
		}
		if maps[i].Dev != maps[j].Dev {
			return maps[i].Dev < maps[j].Dev
		}
		return maps[i].Inode < maps[j].Inode
	})

	return maps, nil
}
