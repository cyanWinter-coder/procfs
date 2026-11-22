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
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewNetIPSocketPartial(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		isUDP      bool
		wantRows   NetIPSocket
		wantErrors []NetIPSocketLineError
		wantErr    bool
	}{
		{
			name:  "tcp partial keeps valid lines and indexes bad ones",
			file:  "testdata/fixtures/proc/net/tcp_partial",
			isUDP: false,
			wantRows: NetIPSocket{
				{
					Sl:        0,
					LocalAddr: net.IP{10, 0, 0, 5},
					LocalPort: 22,
					RemAddr:   net.IP{0, 0, 0, 0},
					RemPort:   0,
					St:        10,
					TxQueue:   0,
					RxQueue:   1,
					UID:       0,
					Inode:     2740,
				},
				{
					Sl:        3,
					LocalAddr: net.IP{0, 0, 0, 0},
					LocalPort: 22,
					RemAddr:   net.IP{0, 0, 0, 0},
					RemPort:   0,
					St:        10,
					TxQueue:   1,
					RxQueue:   1,
					UID:       0,
					Inode:     2742,
				},
			},
			// Header is line 1; the bad local address is line 3 and the
			// truncated line is line 4.
			wantErrors: []NetIPSocketLineError{
				{Line: 3, Category: NetIPSocketErrorField},
				{Line: 4, Category: NetIPSocketErrorFieldCount},
			},
		},
		{
			name:  "tcp6 partial detects unknown address family and malformed field",
			file:  "testdata/fixtures/proc/net/tcp6_partial",
			isUDP: false,
			wantRows: NetIPSocket{
				{
					Sl:        1315,
					LocalAddr: net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					LocalPort: 5355,
					RemAddr:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					RemPort:   0,
					St:        7,
					UID:       981,
					Inode:     21040,
				},
				{
					Sl:        6073,
					LocalAddr: net.IP{254, 128, 0, 0, 0, 0, 0, 0, 86, 225, 173, 255, 254, 124, 102, 9},
					LocalPort: 51073,
					RemAddr:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					RemPort:   0,
					St:        7,
					UID:       1000,
					Inode:     11337031,
				},
			},
			wantErrors: []NetIPSocketLineError{
				{Line: 3, Category: NetIPSocketErrorAddressFamily},
				{Line: 4, Category: NetIPSocketErrorField},
			},
		},
		{
			name:  "udp partial includes drops for valid lines only",
			file:  "testdata/fixtures/proc/net/udp_partial",
			isUDP: true,
			wantRows: NetIPSocket{
				{
					Sl:        0,
					LocalAddr: net.IP{10, 0, 0, 5},
					LocalPort: 22,
					RemAddr:   net.IP{0, 0, 0, 0},
					RemPort:   0,
					St:        10,
					RxQueue:   1,
					Inode:     2740,
					Drops:     intToU64(0),
				},
				{
					Sl:        1,
					LocalAddr: net.IP{4, 3, 2, 1},
					LocalPort: 32,
					RemAddr:   net.IP{8, 7, 6, 5},
					RemPort:   33,
					St:        7,
					TxQueue:   1,
					RxQueue:   2,
					Inode:     2741,
					Drops:     intToU64(7),
				},
				{
					Sl:        3,
					LocalAddr: net.IP{0, 0, 0, 0},
					LocalPort: 22,
					RemAddr:   net.IP{0, 0, 0, 0},
					RemPort:   0,
					St:        10,
					TxQueue:   1,
					RxQueue:   1,
					Inode:     2742,
					Drops:     intToU64(5),
				},
			},
			wantErrors: []NetIPSocketLineError{
				// Truncated line and the line with a non-numeric drops field.
				{Line: 4, Category: NetIPSocketErrorFieldCount},
				{Line: 6, Category: NetIPSocketErrorField},
			},
		},
		{
			name:    "file not found",
			file:    "testdata/fixtures/proc/net/does-not-exist",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newNetIPSocketPartial(tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newNetIPSocketPartial() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if diff := cmp.Diff(tt.wantRows, got.Rows); diff != "" {
				t.Fatalf("unexpected rows (-want +got):\n%s", diff)
			}
			if len(got.LineErrors) != len(tt.wantErrors) {
				t.Fatalf("got %d line errors %+v, want %d", len(got.LineErrors), got.LineErrors, len(tt.wantErrors))
			}
			for i, want := range tt.wantErrors {
				if got.LineErrors[i].Line != want.Line {
					t.Errorf("error %d: got line %d, want line %d", i, got.LineErrors[i].Line, want.Line)
				}
				if got.LineErrors[i].Category != want.Category {
					t.Errorf("error %d: got category %q, want %q", i, got.LineErrors[i].Category, want.Category)
				}
				if got.LineErrors[i].Err == nil {
					t.Errorf("error %d: underlying error is nil", i)
				}
				if !errors.Is(got.LineErrors[i].Err, ErrFileParse) {
					t.Errorf("error %d: does not wrap ErrFileParse: %v", i, got.LineErrors[i].Err)
				}
			}
			if got.Complete() {
				t.Errorf("Complete() = true, want false for a file with bad lines")
			}
		})
	}
}

func TestNewNetIPSocketPartialComplete(t *testing.T) {
	result, err := newNetIPSocketPartial("testdata/fixtures/proc/net/tcp")
	if err != nil {
		t.Fatalf("newNetIPSocketPartial() error = %v", err)
	}
	if !result.Complete() {
		t.Errorf("Complete() = false for a file without bad lines: %+v", result.LineErrors)
	}
	if len(result.Rows) != 3 {
		t.Errorf("got %d rows, want 3", len(result.Rows))
	}
}

func TestParseNetIPSocketUnknownAddressFamily(t *testing.T) {
	// 3-byte address decodes as hex but matches neither IPv4 nor IPv6.
	fields := []string{"1:", "000000:0000", "00000000:0000", "07", "0:0", "0", "0", "10", "0", "39309"}
	_, err := parseNetIPSocketLine(fields, false)
	if err == nil {
		t.Fatal("expected error for unknown address family")
	}
	if category := netIPSocketErrorCategory(err); category != NetIPSocketErrorAddressFamily {
		t.Fatalf("category = %q, want %q", category, NetIPSocketErrorAddressFamily)
	}
	if !errors.Is(err, ErrFileParse) || !errors.Is(err, errUnknownAddressFamily) {
		t.Fatalf("error %v does not wrap the expected sentinels", err)
	}
}

func TestParseNetIPSocketLineNoZeroSocketOnError(t *testing.T) {
	// A short UDP line must never produce a partially populated socket,
	// even though the first 10 fields would otherwise be parseable.
	fields := []string{"1:", "00000000:0000", "00000000:0000", "07", "0:0", "0", "0", "10", "0", "39309"}
	line, err := parseNetIPSocketLine(fields, true)
	if err == nil {
		t.Fatal("expected field count error for short UDP line")
	}
	if line != nil {
		t.Fatalf("got non-nil socket %+v on parse error", line)
	}
	if category := netIPSocketErrorCategory(err); category != NetIPSocketErrorFieldCount {
		t.Fatalf("category = %q, want %q", category, NetIPSocketErrorFieldCount)
	}
}

func TestParseNetIPSocketRowOrder(t *testing.T) {
	result, err := newNetIPSocketPartial("testdata/fixtures/proc/net/tcp")
	if err != nil {
		t.Fatalf("newNetIPSocketPartial() error = %v", err)
	}
	wantSl := []uint64{0, 1, 2}
	for i, row := range result.Rows {
		if row.Sl != wantSl[i] {
			t.Fatalf("row %d Sl = %d, want %d (kernel file order not preserved)", i, row.Sl, wantSl[i])
		}
	}
}

func TestParseNetIPSocketConcurrent(t *testing.T) {
	// Every invocation owns its scanner and result slice; concurrent reads of
	// the same file must return identical, independent results.
	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]NetIPSocketPartialResult, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = newNetIPSocketPartial("testdata/fixtures/proc/net/udp_partial")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: unexpected error %v", i, err)
		}
	}
	want := results[0]
	if want.Complete() {
		t.Fatal("expected partial result with recorded errors")
	}
	for i := 1; i < goroutines; i++ {
		if diff := cmp.Diff(want.Rows, results[i].Rows); diff != "" {
			t.Fatalf("goroutine %d rows differ from the first result (-want +got):\n%s", i, diff)
		}
		if len(results[i].LineErrors) != len(want.LineErrors) {
			t.Fatalf("goroutine %d got %d line errors, want %d", i, len(results[i].LineErrors), len(want.LineErrors))
		}
		for j, le := range want.LineErrors {
			got := results[i].LineErrors[j]
			if got.Line != le.Line || got.Category != le.Category || got.Err.Error() != le.Err.Error() {
				t.Fatalf("goroutine %d line error %d = %+v, want %+v", i, j, got, le)
			}
		}
		// Mutating one result must not be visible through another.
		results[i].LineErrors[0].Line = 999
		if results[0].LineErrors[0].Line == 999 {
			t.Fatal("line error slices are shared between concurrent parses")
		}
	}
}

func TestStrictEntriesStillFailOnBadLine(t *testing.T) {
	// The strict entry points keep their historical contract: any bad line
	// fails the whole table and no partial rows are returned.
	if got, err := newNetTCP("testdata/fixtures/proc/net/tcp_partial"); err == nil || got != nil {
		t.Fatalf("newNetTCP() = %v, %v; want nil, error", got, err)
	}
	if got, err := newNetUDP("testdata/fixtures/proc/net/udp_partial"); err == nil || got != nil {
		t.Fatalf("newNetUDP() = %v, %v; want nil, error", got, err)
	}
	if got, err := newNetTCPSummary("testdata/fixtures/proc/net/tcp_partial"); err == nil || got != nil {
		t.Fatalf("newNetTCPSummary() = %v, %v; want nil, error", got, err)
	}
	if got, err := newNetUDPSummary("testdata/fixtures/proc/net/udp_partial"); err == nil || got != nil {
		t.Fatalf("newNetUDPSummary() = %v, %v; want nil, error", got, err)
	}

	// The strict error still carries ErrFileParse and mentions the line.
	_, err := newNetTCP("testdata/fixtures/proc/net/tcp_partial")
	if !errors.Is(err, ErrFileParse) || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("strict error %q does not reference the first bad line", err)
	}
}

func TestNewNetTCPPartialAndSummary(t *testing.T) {
	result, err := newNetTCPPartial("testdata/fixtures/proc/net/tcp_partial")
	if err != nil {
		t.Fatalf("newNetTCPPartial() error = %v", err)
	}
	if result.Complete() {
		t.Fatal("Complete() = true, want false")
	}
	if len(result.Rows) != 2 || len(result.LineErrors) != 2 {
		t.Fatalf("got %d rows and %d errors, want 2 and 2", len(result.Rows), len(result.LineErrors))
	}

	summary, partial, err := newNetTCPSummaryPartial("testdata/fixtures/proc/net/tcp_partial")
	if err != nil {
		t.Fatalf("newNetTCPSummaryPartial() error = %v", err)
	}
	// Only the two healthy sockets contribute to the summary.
	wantSummary := &NetTCPSummary{TxQueueLength: 1, RxQueueLength: 2, UsedSockets: 2}
	if diff := cmp.Diff(wantSummary, summary); diff != "" {
		t.Fatalf("unexpected summary (-want +got):\n%s", diff)
	}
	if partial.Complete() || len(partial.Rows) != 2 {
		t.Fatalf("unexpected partial result: %+v", partial)
	}
}

func TestNewNetUDPPartialAndSummary(t *testing.T) {
	result, err := newNetUDPPartial("testdata/fixtures/proc/net/udp_partial")
	if err != nil {
		t.Fatalf("newNetUDPPartial() error = %v", err)
	}
	if result.Complete() {
		t.Fatal("Complete() = true, want false")
	}
	if len(result.Rows) != 3 || len(result.LineErrors) != 2 {
		t.Fatalf("got %d rows and %d errors, want 3 and 2", len(result.Rows), len(result.LineErrors))
	}

	summary, partial, err := newNetUDPSummaryPartial("testdata/fixtures/proc/net/udp_partial")
	if err != nil {
		t.Fatalf("newNetUDPSummaryPartial() error = %v", err)
	}
	// Drops of the three healthy lines: 0 + 7 + 5 = 12.
	wantSummary := &NetUDPSummary{TxQueueLength: 2, RxQueueLength: 4, UsedSockets: 3, Drops: intToU64(12)}
	if diff := cmp.Diff(wantSummary, summary); diff != "" {
		t.Fatalf("unexpected summary (-want +got):\n%s", diff)
	}
	if partial.Complete() || len(partial.Rows) != 3 {
		t.Fatalf("unexpected partial result: %+v", partial)
	}
}

func TestFSPartialEntryPoints(t *testing.T) {
	fs, err := NewFS(procTestFixtures)
	if err != nil {
		t.Fatalf("failed to open procfs: %v", err)
	}

	tcp, err := fs.NetTCPPartial()
	if err != nil || !tcp.Complete() || len(tcp.Rows) != 3 {
		t.Fatalf("NetTCPPartial() = %+v, %v", tcp, err)
	}
	tcp6, err := fs.NetTCP6Partial()
	if err != nil || !tcp6.Complete() || len(tcp6.Rows) != 2 {
		t.Fatalf("NetTCP6Partial() = %+v, %v", tcp6, err)
	}
	udp, err := fs.NetUDPPartial()
	if err != nil || !udp.Complete() || len(udp.Rows) != 3 {
		t.Fatalf("NetUDPPartial() = %+v, %v", udp, err)
	}
	udp6, err := fs.NetUDP6Partial()
	if err != nil || !udp6.Complete() || len(udp6.Rows) != 2 {
		t.Fatalf("NetUDP6Partial() = %+v, %v", udp6, err)
	}

	if summary, partial, err := fs.NetTCPSummaryPartial(); err != nil || !partial.Complete() || summary == nil {
		t.Fatalf("NetTCPSummaryPartial() = %v, %+v, %v", summary, partial, err)
	}
	if summary, partial, err := fs.NetUDPSummaryPartial(); err != nil || !partial.Complete() || summary == nil {
		t.Fatalf("NetUDPSummaryPartial() = %v, %+v, %v", summary, partial, err)
	}
}
