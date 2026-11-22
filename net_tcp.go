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
	// NetTCP represents the contents of /proc/net/tcp{,6} file without the header.
	NetTCP []*netIPSocketLine

	// NetTCPSummary provides already computed values like the total queue lengths or
	// the total number of used sockets. In contrast to NetTCP it does not collect
	// the parsed lines into a slice.
	NetTCPSummary NetIPSocketSummary

	// NetTCPPartialResult is the tolerant parsing result of a
	// /proc/net/tcp{,6} file: valid rows in kernel file order plus the line
	// numbers and categories of the rejected lines.
	NetTCPPartialResult struct {
		// Rows contains the successfully parsed lines in kernel file order.
		Rows NetTCP
		// LineErrors records the rejected lines with their line numbers.
		LineErrors []NetIPSocketLineError
	}
)

// Complete reports whether the file was parsed without any rejected line.
func (r NetTCPPartialResult) Complete() bool {
	return len(r.LineErrors) == 0
}

// NetTCP returns the IPv4 kernel/networking statistics for TCP datagrams
// read from /proc/net/tcp.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET) instead.
func (fs FS) NetTCP() (NetTCP, error) {
	return newNetTCP(fs.proc.Path("net/tcp"))
}

// NetTCPPartial returns the IPv4 TCP statistics read from /proc/net/tcp
// without failing on individual malformed lines. Successfully parsed lines are
// returned in kernel file order and every rejected line is reported with its
// line number and failure category. Use the result's Complete method to check
// whether the whole file was parsed successfully.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET) instead.
func (fs FS) NetTCPPartial() (NetTCPPartialResult, error) {
	return newNetTCPPartial(fs.proc.Path("net/tcp"))
}

// NetTCP6 returns the IPv6 kernel/networking statistics for TCP datagrams
// read from /proc/net/tcp6.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET6) instead.
func (fs FS) NetTCP6() (NetTCP, error) {
	return newNetTCP(fs.proc.Path("net/tcp6"))
}

// NetTCP6Partial returns the IPv6 TCP statistics read from /proc/net/tcp6
// without failing on individual malformed lines. Successfully parsed lines are
// returned in kernel file order and every rejected line is reported with its
// line number and failure category. Use the result's Complete method to check
// whether the whole file was parsed successfully.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET6) instead.
func (fs FS) NetTCP6Partial() (NetTCPPartialResult, error) {
	return newNetTCPPartial(fs.proc.Path("net/tcp6"))
}

// NetTCPSummary returns already computed statistics like the total queue lengths
// for TCP datagrams read from /proc/net/tcp.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET) instead.
func (fs FS) NetTCPSummary() (*NetTCPSummary, error) {
	return newNetTCPSummary(fs.proc.Path("net/tcp"))
}

// NetTCPSummaryPartial returns the aggregated TCP statistics of the
// successfully parsed lines from /proc/net/tcp together with the tolerant
// parsing result. The summary stays usable even when the file contains
// malformed lines; inspect the result's Complete method for the completion
// state.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET) instead.
func (fs FS) NetTCPSummaryPartial() (*NetTCPSummary, NetTCPPartialResult, error) {
	return newNetTCPSummaryPartial(fs.proc.Path("net/tcp"))
}

// NetTCP6Summary returns already computed statistics like the total queue lengths
// for TCP datagrams read from /proc/net/tcp6.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET6) instead.
func (fs FS) NetTCP6Summary() (*NetTCPSummary, error) {
	return newNetTCPSummary(fs.proc.Path("net/tcp6"))
}

// NetTCP6SummaryPartial returns the aggregated TCP statistics of the
// successfully parsed lines from /proc/net/tcp6 together with the tolerant
// parsing result. The summary stays usable even when the file contains
// malformed lines; inspect the result's Complete method for the completion
// state.
//
// Deprecated: Use github.com/mdlayher/netlink#Conn (with syscall.AF_INET6) instead.
func (fs FS) NetTCP6SummaryPartial() (*NetTCPSummary, NetTCPPartialResult, error) {
	return newNetTCPSummaryPartial(fs.proc.Path("net/tcp6"))
}

// newNetTCP creates a new NetTCP{,6} from the contents of the given file.
func newNetTCP(file string) (NetTCP, error) {
	n, err := newNetIPSocket(file)
	n1 := NetTCP(n)
	return n1, err
}

// newNetTCPPartial parses the given file tolerating malformed lines.
func newNetTCPPartial(file string) (NetTCPPartialResult, error) {
	r, err := newNetIPSocketPartial(file)
	return NetTCPPartialResult{Rows: NetTCP(r.Rows), LineErrors: r.LineErrors}, err
}

func newNetTCPSummary(file string) (*NetTCPSummary, error) {
	n, err := newNetIPSocketSummary(file)
	if n == nil {
		return nil, err
	}
	n1 := NetTCPSummary(*n)
	return &n1, err
}

func newNetTCPSummaryPartial(file string) (*NetTCPSummary, NetTCPPartialResult, error) {
	summary, partial, err := newNetIPSocketSummaryPartial(file)
	if err != nil {
		return nil, NetTCPPartialResult{}, err
	}
	result := NetTCPPartialResult{Rows: NetTCP(partial.Rows), LineErrors: partial.LineErrors}
	if summary == nil {
		return nil, result, nil
	}
	s := NetTCPSummary(*summary)
	return &s, result, nil
}
