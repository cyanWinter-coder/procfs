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

type (
	// NetUDP represents the contents of /proc/net/udp{,6} file without the header.
	NetUDP []*netIPSocketLine

	// NetUDPSummary provides already computed values like the total queue lengths or
	// the total number of used sockets. In contrast to NetUDP it does not collect
	// the parsed lines into a slice.
	NetUDPSummary NetIPSocketSummary

	// NetUDPPartialResult is the tolerant parsing result of a
	// /proc/net/udp{,6} file: valid rows in kernel file order plus the line
	// numbers and categories of the rejected lines.
	NetUDPPartialResult struct {
		// Rows contains the successfully parsed lines in kernel file order.
		Rows NetUDP
		// LineErrors records the rejected lines with their line numbers.
		LineErrors []NetIPSocketLineError
	}
)

// Complete reports whether the file was parsed without any rejected line.
func (r NetUDPPartialResult) Complete() bool {
	return len(r.LineErrors) == 0
}

// NetUDP returns the IPv4 kernel/networking statistics for UDP datagrams
// read from /proc/net/udp.
func (fs FS) NetUDP() (NetUDP, error) {
	return newNetUDP(fs.proc.Path("net/udp"))
}

// NetUDPPartial returns the IPv4 UDP statistics read from /proc/net/udp
// without failing on individual malformed lines. Successfully parsed lines are
// returned in kernel file order and every rejected line is reported with its
// line number and failure category. Use the result's Complete method to check
// whether the whole file was parsed successfully.
func (fs FS) NetUDPPartial() (NetUDPPartialResult, error) {
	return newNetUDPPartial(fs.proc.Path("net/udp"))
}

// NetUDP6 returns the IPv6 kernel/networking statistics for UDP datagrams
// read from /proc/net/udp6.
func (fs FS) NetUDP6() (NetUDP, error) {
	return newNetUDP(fs.proc.Path("net/udp6"))
}

// NetUDP6Partial returns the IPv6 UDP statistics read from /proc/net/udp6
// without failing on individual malformed lines. Successfully parsed lines are
// returned in kernel file order and every rejected line is reported with its
// line number and failure category. Use the result's Complete method to check
// whether the whole file was parsed successfully.
func (fs FS) NetUDP6Partial() (NetUDPPartialResult, error) {
	return newNetUDPPartial(fs.proc.Path("net/udp6"))
}

// NetUDPSummary returns already computed statistics like the total queue lengths
// for UDP datagrams read from /proc/net/udp.
func (fs FS) NetUDPSummary() (*NetUDPSummary, error) {
	return newNetUDPSummary(fs.proc.Path("net/udp"))
}

// NetUDPSummaryPartial returns the aggregated UDP statistics of the
// successfully parsed lines from /proc/net/udp together with the tolerant
// parsing result. The summary stays usable even when the file contains
// malformed lines; inspect the result's Complete method for the completion
// state.
func (fs FS) NetUDPSummaryPartial() (*NetUDPSummary, NetUDPPartialResult, error) {
	return newNetUDPSummaryPartial(fs.proc.Path("net/udp"))
}

// NetUDP6Summary returns already computed statistics like the total queue lengths
// for UDP datagrams read from /proc/net/udp6.
func (fs FS) NetUDP6Summary() (*NetUDPSummary, error) {
	return newNetUDPSummary(fs.proc.Path("net/udp6"))
}

// NetUDP6SummaryPartial returns the aggregated UDP statistics of the
// successfully parsed lines from /proc/net/udp6 together with the tolerant
// parsing result. The summary stays usable even when the file contains
// malformed lines; inspect the result's Complete method for the completion
// state.
func (fs FS) NetUDP6SummaryPartial() (*NetUDPSummary, NetUDPPartialResult, error) {
	return newNetUDPSummaryPartial(fs.proc.Path("net/udp6"))
}

// newNetUDP creates a new NetUDP{,6} from the contents of the given file.
func newNetUDP(file string) (NetUDP, error) {
	n, err := newNetIPSocket(file)
	n1 := NetUDP(n)
	return n1, err
}

// newNetUDPPartial parses the given file tolerating malformed lines.
func newNetUDPPartial(file string) (NetUDPPartialResult, error) {
	r, err := newNetIPSocketPartial(file)
	return NetUDPPartialResult{Rows: NetUDP(r.Rows), LineErrors: r.LineErrors}, err
}

func newNetUDPSummary(file string) (*NetUDPSummary, error) {
	n, err := newNetIPSocketSummary(file)
	if n == nil {
		return nil, err
	}
	n1 := NetUDPSummary(*n)
	return &n1, err
}

func newNetUDPSummaryPartial(file string) (*NetUDPSummary, NetUDPPartialResult, error) {
	summary, partial, err := newNetIPSocketSummaryPartial(file)
	if err != nil {
		return nil, NetUDPPartialResult{}, err
	}
	result := NetUDPPartialResult{Rows: NetUDP(partial.Rows), LineErrors: partial.LineErrors}
	if summary == nil {
		return nil, result, nil
	}
	s := NetUDPSummary(*summary)
	return &s, result, nil
}
