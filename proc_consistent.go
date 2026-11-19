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

	"github.com/prometheus/procfs/internal/parsers"
)

// DefaultConsistentReadRetries is the maximum number of additional attempts a
// consistent read performs after the initial one. It bounds the work done when
// a process exits or its PID is reused while a read is in progress.
const DefaultConsistentReadRetries = 3

var (
	// ErrProcessGone is returned when the process a read was started for can no
	// longer be found in the proc filesystem.
	ErrProcessGone = errors.New("process no longer exists")
	// ErrProcessReused is returned when the PID a read was started for now
	// refers to a different process, i.e. the original process exited and its
	// PID was reused before the read completed.
	ErrProcessReused = errors.New("PID reused by a different process")
)

// processIdentity is the stable identity of a process instance. The start time
// of a process (field 22 of /proc/[pid]/stat, in clock ticks since boot) does
// not change during the lifetime of the process and distinguishes a reused PID
// from the original process.
type processIdentity struct {
	pid       int
	starttime uint64
}

// identity reads the current process identity from /proc/[pid]/stat.
func (p Proc) identity() (processIdentity, error) {
	data, err := parsers.ReadFileNoStat(p.path("stat"))
	if err != nil {
		return processIdentity{}, err
	}
	return parseProcessIdentity(p.PID, data)
}

// parseProcessIdentity extracts the PID and start time from the contents of a
// /proc/[pid]/stat file. Only the fields needed for the identity check are
// parsed so that a malformed tail of the file does not invalidate it.
func parseProcessIdentity(pid int, data []byte) (processIdentity, error) {
	l := bytes.IndexByte(data, '(')
	r := bytes.LastIndexByte(data, ')')
	if l < 0 || r < 0 || r+2 >= len(data) {
		return processIdentity{}, fmt.Errorf("%w: unexpected stat format, couldn't extract comm %q", ErrFileParse, data)
	}

	var (
		// Fields 3 through 21 of /proc/[pid]/stat are skipped; field 22 is
		// starttime. See proc(5).
		state                                   string
		ppid, pgrp, session, tty, tpgid         int
		flags, minFlt, cminFlt, majFlt, cmajFlt uint64
		utime, stime                            uint64
		cutime, cstime                          int64
		priority, nice, numThreads              int
		itrealvalue                             int64
		starttime                               uint64
	)

	if _, err := fmt.Fscan(
		bytes.NewReader(data[r+2:]),
		&state,
		&ppid, &pgrp, &session, &tty, &tpgid,
		&flags, &minFlt, &cminFlt, &majFlt, &cmajFlt,
		&utime, &stime, &cutime, &cstime,
		&priority, &nice, &numThreads,
		&itrealvalue,
		&starttime,
	); err != nil {
		return processIdentity{}, fmt.Errorf("%w: cannot parse starttime from stat %q: %w", ErrFileParse, data, err)
	}

	return processIdentity{pid: pid, starttime: starttime}, nil
}

// consistentReadError wraps one of the sentinel errors (ErrProcessGone,
// ErrProcessReused) with details about the PID while remaining usable with
// errors.Is.
type consistentReadError struct {
	pid       int
	starttime uint64
	err       error
}

func (e *consistentReadError) Error() string {
	return fmt.Sprintf("%s (pid %d, starttime %d)", e.err.Error(), e.pid, e.starttime)
}

func (e *consistentReadError) Unwrap() error { return e.err }

// identityFailure maps a failed identity read to the error the caller sees:
// a missing process is reported as ErrProcessGone; any other failure (for
// example a stat file that cannot be parsed while the PID is being recycled)
// is wrapped so the underlying cause stays inspectable.
func identityFailure(pid int, starttime uint64, err error) error {
	if os.IsNotExist(err) {
		return &consistentReadError{pid: pid, starttime: starttime, err: ErrProcessGone}
	}
	return fmt.Errorf("cannot verify process identity for pid %d: %w", pid, err)
}

// identityHookPhase identifies the point of an attempt an identityHook
// invocation belongs to.
type identityHookPhase int

const (
	// identityHookPreRead fires before the identity read that opens an attempt.
	identityHookPreRead identityHookPhase = iota
	// identityHookPostRead fires before the identity read that closes an
	// attempt, i.e. after readFn has run.
	identityHookPostRead
)

// identityHook, when non-nil, is invoked before every identity read with the
// attempt number and which check of the attempt it is. It exists to make races
// deterministic in tests and is nil in production builds.
var identityHook func(attempt int, phase identityHookPhase)

// readConsistently runs readFn while verifying that the same process instance
// is present before and after every attempt. If the process exits or its PID is
// reused during an attempt, the attempt is discarded and retried. At most
// maxRetries retries are performed after the initial attempt, so the function
// can never loop indefinitely. A successful attempt returns the value produced
// by readFn; no partial result is ever returned.
func readConsistently[T any](p Proc, maxRetries int, readFn func() (T, error)) (T, error) {
	var zero T

	if maxRetries < 0 {
		maxRetries = 0
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if identityHook != nil {
			identityHook(attempt, identityHookPreRead)
		}
		want, err := p.identity()
		if err != nil {
			// The process is already gone (or unreadable) before the attempt:
			// retry while attempts remain, otherwise report it as gone.
			lastErr = identityFailure(p.PID, 0, err)
			continue
		}

		v, readErr := readFn()

		if identityHook != nil {
			identityHook(attempt, identityHookPostRead)
		}
		got, idErr := p.identity()
		if idErr != nil {
			// The post-read identity cannot be established. Whether the
			// process exited or stat is temporarily unreadable, the data read
			// by this attempt cannot be proven consistent, so it is discarded.
			lastErr = identityFailure(p.PID, want.starttime, idErr)
			continue
		}

		if got.starttime != want.starttime || got.pid != want.pid {
			lastErr = &consistentReadError{pid: p.PID, starttime: want.starttime, err: ErrProcessReused}
			continue
		}

		// Identity confirmed: the data produced by this attempt belongs to a
		// single process instance. Surface the read error, if any.
		if readErr != nil {
			return zero, readErr
		}
		return v, nil
	}

	return zero, lastErr
}

// Consistent runs fn against the process and returns its result only if the
// process identity (its start time, read from /proc/[pid]/stat) is unchanged
// between the beginning and the end of the call. This guarantees that the
// files fn reads all belong to the same process instance even when the process
// exits and its PID is reused concurrently.
//
// When the process disappears or its PID is reused while fn is running, the
// partial result is discarded and the call is retried, up to
// DefaultConsistentReadRetries times. If every attempt fails the identity
// check, an error wrapping ErrProcessGone or ErrProcessReused is returned and
// no partial result is exposed. Errors returned by fn itself (for example a
// missing optional file) are only returned after the identity check succeeds.
//
// The single-file Proc accessors (Stat, CmdLine, IO, ...) are unchanged; this
// method is intended for reads that combine several files, for example:
//
//	var stat ProcStat
//	var io ProcIO
//	err := p.Consistent(func() error {
//	    var err error
//	    stat, err = p.Stat()
//	    if err != nil {
//	        return err
//	    }
//	    io, err = p.IO()
//	    return err
//	})
func (p Proc) Consistent(fn func() error) error {
	_, err := readConsistently(p, DefaultConsistentReadRetries, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
