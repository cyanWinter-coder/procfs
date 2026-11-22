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
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadNetUNIXPartial(t *testing.T) {
	result, err := readNetUNIXPartial("testdata/fixtures/proc/net/unix_partial")
	if err != nil {
		t.Fatalf("readNetUNIXPartial() error = %v", err)
	}
	if result.Complete() {
		t.Fatal("Complete() = true, want false for a file with bad lines")
	}

	wantRows := []*NetUNIXLine{
		{
			KernelPtr: "0000000000000000",
			RefCount:  2,
			Flags:     1 << 16,
			Type:      1,
			State:     1,
			Inode:     3442596,
			Path:      "/var/run/postgresql/.s.PGSQL.5432",
		},
		{
			KernelPtr: "0000000000000000",
			RefCount:  3,
			Type:      1,
			State:     3,
			Inode:     4787297,
			Path:      "/var/run/postgresql/.s.PGSQL.5432",
		},
	}
	if diff := cmp.Diff(wantRows, result.Rows); diff != "" {
		t.Fatalf("unexpected rows (-want +got):\n%s", diff)
	}

	// Header is line 1; the short line is line 3 and the bad state is line 4.
	wantErrors := []NetUNIXLineError{
		{Line: 3, Category: NetUNIXErrorFieldCount},
		{Line: 4, Category: NetUNIXErrorField},
	}
	if len(result.LineErrors) != len(wantErrors) {
		t.Fatalf("got %d line errors %+v, want %d", len(result.LineErrors), result.LineErrors, len(wantErrors))
	}
	for i, want := range wantErrors {
		if result.LineErrors[i].Line != want.Line {
			t.Errorf("error %d: got line %d, want line %d", i, result.LineErrors[i].Line, want.Line)
		}
		if result.LineErrors[i].Category != want.Category {
			t.Errorf("error %d: got category %q, want %q", i, result.LineErrors[i].Category, want.Category)
		}
		if !errors.Is(result.LineErrors[i].Err, ErrFileParse) {
			t.Errorf("error %d: does not wrap ErrFileParse: %v", i, result.LineErrors[i].Err)
		}
	}
}

func TestReadNetUNIXPartialComplete(t *testing.T) {
	result, err := readNetUNIXPartial("testdata/fixtures/proc/net/unix")
	if err != nil {
		t.Fatalf("readNetUNIXPartial() error = %v", err)
	}
	if !result.Complete() {
		t.Errorf("Complete() = false for a file without bad lines: %+v", result.LineErrors)
	}
	if len(result.Rows) != 5 {
		t.Errorf("got %d rows, want 5", len(result.Rows))
	}
}

func TestReadNetUNIXStrictStillFails(t *testing.T) {
	// The strict entry point keeps the historical contract.
	got, err := readNetUNIX("testdata/fixtures/proc/net/unix_partial")
	if err == nil {
		t.Fatalf("readNetUNIX() error = nil, want error; got %+v", got)
	}
	if got != nil {
		t.Fatalf("readNetUNIX() = %+v, want nil on error", got)
	}
	if !errors.Is(err, ErrFileParse) {
		t.Fatalf("error %v does not wrap ErrFileParse", err)
	}
}

func TestReadNetUNIXPartialRowOrder(t *testing.T) {
	result, err := readNetUNIXPartial("testdata/fixtures/proc/net/unix")
	if err != nil {
		t.Fatalf("readNetUNIXPartial() error = %v", err)
	}
	wantInodes := []uint64{3442596, 10061, 12392, 4787297, 5091797}
	for i, row := range result.Rows {
		if row.Inode != wantInodes[i] {
			t.Fatalf("row %d Inode = %d, want %d (kernel file order not preserved)", i, row.Inode, wantInodes[i])
		}
	}
}

func TestReadNetUNIXPartialConcurrent(t *testing.T) {
	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]NetUNIXPartialResult, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = readNetUNIXPartial("testdata/fixtures/proc/net/unix_partial")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: unexpected error %v", i, err)
		}
	}
	for i := 1; i < goroutines; i++ {
		if diff := cmp.Diff(results[0].Rows, results[i].Rows); diff != "" {
			t.Fatalf("goroutine %d rows differ from the first result (-want +got):\n%s", i, diff)
		}
		if len(results[i].LineErrors) != len(results[0].LineErrors) {
			t.Fatalf("goroutine %d got %d line errors, want %d", i, len(results[i].LineErrors), len(results[0].LineErrors))
		}
		for j, le := range results[0].LineErrors {
			got := results[i].LineErrors[j]
			if got.Line != le.Line || got.Category != le.Category || got.Err.Error() != le.Err.Error() {
				t.Fatalf("goroutine %d line error %d = %+v, want %+v", i, j, got, le)
			}
		}
		results[i].LineErrors[0].Line = 999
		if results[0].LineErrors[0].Line == 999 {
			t.Fatal("line error slices are shared between concurrent parses")
		}
	}
}

func TestFSNetUNIXPartial(t *testing.T) {
	fs, err := NewFS(procTestFixtures)
	if err != nil {
		t.Fatalf("failed to open procfs: %v", err)
	}

	result, err := fs.NetUNIXPartial()
	if err != nil {
		t.Fatalf("NetUNIXPartial() error = %v", err)
	}
	if !result.Complete() || len(result.Rows) != 5 {
		t.Fatalf("NetUNIXPartial() = %+v", result)
	}

	// The strict entry point remains available and compatible.
	strict, err := fs.NetUNIX()
	if err != nil {
		t.Fatalf("NetUNIX() error = %v", err)
	}
	if len(strict.Rows) != 5 {
		t.Fatalf("NetUNIX() returned %d rows, want 5", len(strict.Rows))
	}
}
