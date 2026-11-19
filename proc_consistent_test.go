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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// statLine builds a minimal but valid /proc/[pid]/stat line whose field 22
// (starttime) is the given value.
func statLine(pid int, comm string, starttime uint64) []byte {
	return []byte(fmt.Sprintf(
		"%d (%s) R 1 1 1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
		pid, comm, starttime,
	))
}

// consistentTestProc creates a temp proc filesystem containing one process
// with a stat file (starttime 100) and a few readable data files.
func consistentTestProc(t *testing.T, pid int) (FS, Proc, string) {
	t.Helper()

	root := t.TempDir()
	procDir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "stat"), statLine(pid, "testproc", 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("testproc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("testproc\x00--arg\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	p, err := fs.Proc(pid)
	if err != nil {
		t.Fatal(err)
	}
	return fs, p, procDir
}

// withIdentityHook installs a hook invoked before every identity read and
// restores the previous hook when the test ends.
func withIdentityHook(t *testing.T, hook func(attempt int, phase identityHookPhase)) {
	t.Helper()
	old := identityHook
	identityHook = hook
	t.Cleanup(func() { identityHook = old })
}

// TestParseProcessIdentity checks the start time extraction used by the
// identity check against the real fixture layout.
func TestParseProcessIdentity(t *testing.T) {
	data := []byte("26231 (vim) R 5392 7446 5392 34835 7446 4218880 32533 309516 26 82 1677 44 158 99 20 0 1 0 82375 56274944 1981 18446744073709551615 4194304 6294284 140736914091744 140736914087944 139965136429984 0 0 12288 1870679807 0 0 0 17 0 0 0 31 0 0 8391624 8481048 16420864 140736914093252 140736914093279 140736914093279 140736914096107 0")

	id, err := parseProcessIdentity(26231, data)
	if err != nil {
		t.Fatal(err)
	}
	if id.pid != 26231 {
		t.Errorf("want pid 26231, have %d", id.pid)
	}
	if id.starttime != 82375 {
		t.Errorf("want starttime 82375, have %d", id.starttime)
	}

	if _, err := parseProcessIdentity(1, []byte("no parens here")); !errors.Is(err, ErrFileParse) {
		t.Errorf("want ErrFileParse for malformed stat, have %v", err)
	}
}

// TestConsistentHappyPath verifies that a multi-file read succeeds and returns
// data from a single process instance when nothing changes underneath it.
func TestConsistentHappyPath(t *testing.T) {
	_, p, _ := consistentTestProc(t, 4242)

	var (
		comm    string
		cmdline []string
	)
	err := p.Consistent(func() error {
		var err error
		comm, err = p.Comm()
		if err != nil {
			return err
		}
		cmdline, err = p.CmdLine()
		return err
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comm != "testproc" {
		t.Errorf("want comm testproc, have %q", comm)
	}
	if want := []string{"testproc", "--arg"}; fmt.Sprint(cmdline) != fmt.Sprint(want) {
		t.Errorf("want cmdline %v, have %v", want, cmdline)
	}
}

// TestConsistentProcessRestart simulates the original process exiting and its
// PID being reused while the read is in progress. The first attempt must be
// discarded and the second attempt must read the new process consistently.
func TestConsistentProcessRestart(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4243)
	statPath := filepath.Join(procDir, "stat")

	var identityReads int
	withIdentityHook(t, func(attempt int, phase identityHookPhase) {
		identityReads++
		// Between the data read and the closing identity check of the first
		// attempt, replace the process with a different instance carrying the
		// same PID. The post-read check then detects the reuse and attempt 1
		// is discarded.
		if attempt == 0 && phase == identityHookPostRead {
			if err := os.WriteFile(statPath, statLine(4243, "reused", 999), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	})

	var comm string
	err := p.Consistent(func() error {
		var err error
		comm, err = p.Comm()
		return err
	})
	if err != nil {
		t.Fatalf("want successful retry after PID reuse, have error: %v", err)
	}
	// The first attempt was discarded; the result must come from the new
	// process instance.
	if comm != "testproc" {
		t.Errorf("want comm from the surviving process (testproc), have %q", comm)
	}
	// Two attempts means at least three identity reads (pre/post attempt 1,
	// pre attempt 2).
	if identityReads < 3 {
		t.Errorf("want at least one full retry cycle (3 identity reads), have %d", identityReads)
	}
}

// TestConsistentPIDReuseExhausted verifies that when every attempt observes a
// different process instance, the caller gets ErrProcessReused and no partial
// result rather than mixed data.
func TestConsistentPIDReuseExhausted(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4244)
	statPath := filepath.Join(procDir, "stat")

	// Change the identity between the data read and the closing identity check
	// of every attempt, so the post-read check always observes a different
	// process instance.
	var flips int
	withIdentityHook(t, func(attempt int, phase identityHookPhase) {
		if phase != identityHookPostRead {
			return
		}
		flips++
		if err := os.WriteFile(statPath, statLine(4244, "flip", uint64(100+flips)), 0o644); err != nil {
			t.Fatal(err)
		}
	})

	var called int
	err := p.Consistent(func() error {
		called++
		return nil
	})
	if !errors.Is(err, ErrProcessReused) {
		t.Fatalf("want ErrProcessReused, have %v", err)
	}
	// Initial attempt + DefaultConsistentReadRetries retries, and never more.
	if want := DefaultConsistentReadRetries + 1; called != want {
		t.Errorf("want %d attempts, have %d", want, called)
	}
}

// TestConsistentProcessExits simulates the process disappearing mid-read and
// staying gone. The error must wrap ErrProcessGone, attempts must be bounded,
// and no partial result must be returned.
func TestConsistentProcessExits(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4245)
	statPath := filepath.Join(procDir, "stat")

	var identityReads int
	withIdentityHook(t, func(attempt int, phase identityHookPhase) {
		identityReads++
		// Remove the stat file between the data read and the closing identity
		// check of the first attempt: the post-read check then fails and the
		// process stays gone for every later attempt.
		if attempt == 0 && phase == identityHookPostRead {
			if err := os.Remove(statPath); err != nil {
				t.Fatal(err)
			}
		}
	})

	fnRan := false
	err := p.Consistent(func() error {
		fnRan = true
		return nil
	})
	if !errors.Is(err, ErrProcessGone) {
		t.Fatalf("want ErrProcessGone, have %v", err)
	}
	if !fnRan {
		t.Fatal("read function should have run during the first attempt")
	}
	// At most two identity reads per attempt and one attempt per bounded retry.
	if want := 2 * (DefaultConsistentReadRetries + 1); identityReads > want {
		t.Errorf("too many identity reads (%d > %d): retry loop is not bounded", identityReads, want)
	}
}

// TestConsistentFileVanishes verifies that a data file disappearing inside the
// callback is reported as a plain read error once identity is confirmed, rather
// than as a process-level error, and does not cause an unbounded loop.
func TestConsistentFileVanishes(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4246)
	commPath := filepath.Join(procDir, "comm")

	var calls int
	err := p.Consistent(func() error {
		calls++
		if err := os.Remove(commPath); err != nil {
			return err
		}
		_, err := p.Comm()
		return err
	})
	if err == nil {
		t.Fatal("want error for vanished file, have nil")
	}
	if errors.Is(err, ErrProcessGone) || errors.Is(err, ErrProcessReused) {
		t.Fatalf("want a file read error, not an identity error: %v", err)
	}
	if !os.IsNotExist(err) {
		t.Errorf("want os.IsNotExist error, have %v", err)
	}
	if calls != 1 {
		t.Errorf("file errors with confirmed identity must not retry, have %d calls", calls)
	}
}

// TestConsistentTransientUnreadableStat covers the case where stat exists but
// briefly cannot be parsed (for example while a PID is being recycled). The
// unreadable attempt is discarded and, once the content is valid again, the
// read succeeds.
func TestConsistentTransientUnreadableStat(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4249)
	statPath := filepath.Join(procDir, "stat")

	var attempts int
	withIdentityHook(t, func(attempt int, phase identityHookPhase) {
		// Corrupt the closing identity check of the first attempt only.
		if attempt == 0 && phase == identityHookPostRead {
			if err := os.WriteFile(statPath, []byte("garbage without parens"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if attempt == 1 && phase == identityHookPreRead {
			// The process is healthy again (same identity as at the start).
			if err := os.WriteFile(statPath, statLine(4249, "testproc", 100), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	})

	err := p.Consistent(func() error {
		attempts++
		return nil
	})
	if err != nil {
		t.Fatalf("want recovery after a transient unreadable stat, have: %v", err)
	}
	if attempts != 2 {
		t.Errorf("want 2 attempts, have %d", attempts)
	}
}

// TestConsistentRetryBound makes the retry limit explicit: readConsistently
// must run at most maxRetries+1 attempts and return the last identity error.
func TestConsistentRetryBound(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4247)
	statPath := filepath.Join(procDir, "stat")

	const max = 2
	var attempts int
	_, err := readConsistently(p, max, func() (struct{}, error) {
		attempts++
		// Change identity during every attempt.
		if err := os.WriteFile(statPath, statLine(4247, "x", uint64(100+attempts)), 0o644); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	})
	if !errors.Is(err, ErrProcessReused) {
		t.Fatalf("want ErrProcessReused, have %v", err)
	}
	if want := max + 1; attempts != want {
		t.Errorf("want exactly %d attempts, have %d", want, attempts)
	}
}

// TestConsistentConcurrentReaders exercises the snapshot path under concurrent
// access; it must never panic and must never return mixed data (each successful
// call sees one stable identity).
func TestConsistentConcurrentReaders(t *testing.T) {
	_, p, procDir := consistentTestProc(t, 4248)
	statPath := filepath.Join(procDir, "stat")

	const goroutines = 16
	const iterations = 50

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	// Background "process churn": repeatedly replace the stat file with new
	// process instances under the same PID. It runs a bounded number of rounds
	// so the test always terminates.
	var churnWG sync.WaitGroup
	churnWG.Add(1)
	var churn atomic.Uint64
	go func() {
		defer churnWG.Done()
		for i := 0; i < 200; i++ {
			tick := churn.Add(1)
			_ = os.WriteFile(statPath, statLine(4248, "churn", 100+tick%4), 0o644)
		}
	}()

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				var comm string
				err := p.Consistent(func() error {
					var err error
					comm, err = p.Comm()
					return err
				})
				if err != nil {
					// On a real proc filesystem stat updates are atomic; on the
					// plain test filesystem a concurrent rewrite can briefly be
					// truncated, which surfaces as an identity failure. Both
					// conditions must be reported as identifiable errors, never
					// as partial data.
					if !errors.Is(err, ErrProcessGone) &&
						!errors.Is(err, ErrProcessReused) &&
						!errors.Is(err, ErrFileParse) {
						errs <- fmt.Errorf("unexpected error: %w", err)
						return
					}
					continue
				}
				if comm != "testproc" {
					errs <- fmt.Errorf("unexpected comm %q", comm)
					return
				}
			}
		}()
	}

	wg.Wait()
	churnWG.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestConsistentOnFixtures runs the snapshot read against the checked-in proc
// fixtures to make sure the identity check works with real-world stat content.
func TestConsistentOnFixtures(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26231)
	if err != nil {
		t.Fatal(err)
	}

	var stat ProcStat
	if err := p.Consistent(func() error {
		var err error
		stat, err = p.Stat()
		return err
	}); err != nil {
		t.Fatalf("consistent read on fixtures failed: %v", err)
	}
	if stat.Starttime != 82375 {
		t.Errorf("want starttime 82375, have %d", stat.Starttime)
	}
}
