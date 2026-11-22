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
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// Maximum size limit used by io.LimitReader while reading the content of the
	// /proc/net/udp{,6} files. The number of lines inside such a file is dynamic
	// as each line represents a single used socket.
	// In theory, the number of available sockets is 65535 (2^16 - 1) per IP.
	// With e.g. 150 Byte per line and the maximum number of 65535,
	// the reader needs to handle 150 Byte * 65535 =~ 10 MB for a single IP.
	readLimit = 4294967296 // Byte -> 4 GiB
)

// Categories of per-line parse failures reported by the tolerant network
// table parsers.
const (
	// NetIPSocketErrorFieldCount means a line does not carry the expected
	// number of fields.
	NetIPSocketErrorFieldCount = "field count mismatch"
	// NetIPSocketErrorAddressFamily means an address can neither be decoded
	// as an IPv4 nor an IPv6 address, so the address family is unknown.
	NetIPSocketErrorAddressFamily = "unknown address family"
	// NetIPSocketErrorField means one of the present fields cannot be parsed.
	NetIPSocketErrorField = "malformed field"
)

// This contains generic data structures for both udp and tcp sockets.
type (
	// NetIPSocket represents the contents of /proc/net/{t,u}dp{,6} file without the header.
	NetIPSocket []*netIPSocketLine

	// NetIPSocketSummary provides already computed values like the total queue lengths or
	// the total number of used sockets. In contrast to NetIPSocket it does not collect
	// the parsed lines into a slice.
	NetIPSocketSummary struct {
		// TxQueueLength shows the total queue length of all parsed tx_queue lengths.
		TxQueueLength uint64
		// RxQueueLength shows the total queue length of all parsed rx_queue lengths.
		RxQueueLength uint64
		// UsedSockets shows the total number of parsed lines representing the
		// number of used sockets.
		UsedSockets uint64
		// Drops shows the total number of dropped packets of all UDP sockets.
		Drops *uint64
	}

	// A single line parser for fields from /proc/net/{t,u}dp{,6}.
	// Fields which are not used by IPSocket are skipped.
	// Drops is non-nil for udp{,6}, but nil for tcp{,6}.
	// For the proc file format details, see https://linux.die.net/man/5/proc.
	netIPSocketLine struct {
		Sl        uint64
		LocalAddr net.IP
		LocalPort uint64
		RemAddr   net.IP
		RemPort   uint64
		St        uint64
		TxQueue   uint64
		RxQueue   uint64
		UID       uint64
		Inode     uint64
		Drops     *uint64
	}

	// NetIPSocketLineError describes a single line that could not be parsed.
	// Line numbers are 1-based and include the header line, matching the line
	// numbers seen when opening the kernel file directly.
	NetIPSocketLineError struct {
		// Line is the 1-based line number within the source file.
		Line int
		// Category classifies the failure, see the NetIPSocketError* constants.
		Category string
		// Err is the underlying parse error.
		Err error
	}

	// NetIPSocketPartialResult is the tolerant parsing result of a
	// /proc/net/{t,u}dp{,6} file. Valid lines are kept in Rows while every
	// rejected line is recorded in LineErrors together with its line number
	// and failure category.
	NetIPSocketPartialResult struct {
		// Rows contains the successfully parsed lines in kernel file order.
		Rows NetIPSocket
		// LineErrors records the rejected lines with their line numbers.
		LineErrors []NetIPSocketLineError
	}
)

// Complete reports whether the file was parsed without any rejected line.
func (r NetIPSocketPartialResult) Complete() bool {
	return len(r.LineErrors) == 0
}

func (e NetIPSocketLineError) Error() string {
	return fmt.Sprintf("%s: line %d: %s: %s", ErrFileParse, e.Line, e.Category, e.Err)
}

// Unwrap exposes both the parser sentinel and the underlying line error so
// errors.Is matches either.
func (e NetIPSocketLineError) Unwrap() []error {
	return []error{ErrFileParse, e.Err}
}

// firstLineError returns the first recorded line error, or nil. It is shared by
// the strict entry points, which keep the historical contract of failing the
// whole table on the first bad line.
func (r NetIPSocketPartialResult) firstLineError() error {
	if len(r.LineErrors) == 0 {
		return nil
	}
	return r.LineErrors[0]
}

func newNetIPSocket(file string) (NetIPSocket, error) {
	result, err := newNetIPSocketPartial(file)
	if err != nil {
		return nil, err
	}
	if err := result.firstLineError(); err != nil {
		return nil, err
	}
	return result.Rows, nil
}

// newNetIPSocketPartial parses the given file line by line. Valid lines are
// returned together with the line numbers and categories of the rejected
// lines instead of failing the whole table on the first bad line.
func newNetIPSocketPartial(file string) (NetIPSocketPartialResult, error) {
	f, err := os.Open(file)
	if err != nil {
		return NetIPSocketPartialResult{}, err
	}
	defer f.Close()

	return parseNetIPSocket(io.LimitReader(f, readLimit), strings.Contains(file, "udp"))
}

// parseNetIPSocket scans the stream of a /proc/net/{t,u}dp{,6} file. The
// scanner and its line slice are local to this call, so concurrent parses never
// share mutable state. Rows keep the kernel file order.
func parseNetIPSocket(r io.Reader, isUDP bool) (NetIPSocketPartialResult, error) {
	var result NetIPSocketPartialResult

	s := bufio.NewScanner(r)
	lineNo := 0
	s.Scan() // skip first line with headers
	lineNo++
	for s.Scan() {
		lineNo++
		fields := strings.Fields(s.Text())
		line, err := parseNetIPSocketLine(fields, isUDP)
		if err != nil {
			result.LineErrors = append(result.LineErrors, NetIPSocketLineError{
				Line:     lineNo,
				Category: netIPSocketErrorCategory(err),
				Err:      err,
			})
			continue
		}
		result.Rows = append(result.Rows, line)
	}
	if err := s.Err(); err != nil {
		return NetIPSocketPartialResult{}, err
	}
	return result, nil
}

// newNetIPSocketSummary creates a new NetIPSocket{,6} from the contents of the given file.
func newNetIPSocketSummary(file string) (*NetIPSocketSummary, error) {
	result, err := newNetIPSocketPartial(file)
	if err != nil {
		return nil, err
	}
	if err := result.firstLineError(); err != nil {
		return nil, err
	}
	return summarizeNetIPSocket(result.Rows, strings.Contains(file, "udp")), nil
}

// newNetIPSocketSummaryPartial tolerates rejected lines and aggregates only the
// successfully parsed ones. The completion state is available through the
// returned result's Complete method.
func newNetIPSocketSummaryPartial(file string) (*NetIPSocketSummary, NetIPSocketPartialResult, error) {
	result, err := newNetIPSocketPartial(file)
	if err != nil {
		return nil, NetIPSocketPartialResult{}, err
	}
	return summarizeNetIPSocket(result.Rows, strings.Contains(file, "udp")), result, nil
}

func summarizeNetIPSocket(lines NetIPSocket, isUDP bool) *NetIPSocketSummary {
	var summary NetIPSocketSummary
	var udpPacketDrops uint64
	for _, line := range lines {
		summary.TxQueueLength += line.TxQueue
		summary.RxQueueLength += line.RxQueue
		summary.UsedSockets++
		if isUDP {
			udpPacketDrops += *line.Drops
			summary.Drops = &udpPacketDrops
		}
	}
	return &summary
}

// netIPSocketErrorCategory maps a line parse error to one of the
// NetIPSocketError* categories.
func netIPSocketErrorCategory(err error) string {
	switch {
	case errors.Is(err, errUnknownAddressFamily):
		return NetIPSocketErrorAddressFamily
	case errors.Is(err, errNetIPSocketFieldCount):
		return NetIPSocketErrorFieldCount
	default:
		return NetIPSocketErrorField
	}
}

// the /proc/net/{t,u}dp{,6} files are network byte order for ipv4 and for ipv6 the address is four words consisting of four bytes each. In each of those four words the four bytes are written in reverse order.

// errUnknownAddressFamily marks an address whose decoded length is neither 4
// nor 16 bytes, i.e. neither IPv4 nor IPv6.
var errUnknownAddressFamily = errors.New("unknown address family")

// errNetIPSocketFieldCount marks a line carrying fewer fields than the parser
// needs.
var errNetIPSocketFieldCount = errors.New("unexpected number of fields")

func parseIP(hexIP string) (net.IP, error) {
	var byteIP []byte
	byteIP, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, fmt.Errorf("%w: Cannot parse socket field in %q: %w", ErrFileParse, hexIP, err)
	}
	switch len(byteIP) {
	case 4:
		return net.IP{byteIP[3], byteIP[2], byteIP[1], byteIP[0]}, nil
	case 16:
		i := net.IP{
			byteIP[3], byteIP[2], byteIP[1], byteIP[0],
			byteIP[7], byteIP[6], byteIP[5], byteIP[4],
			byteIP[11], byteIP[10], byteIP[9], byteIP[8],
			byteIP[15], byteIP[14], byteIP[13], byteIP[12],
		}
		return i, nil
	default:
		return nil, fmt.Errorf("%w: %w: unable to parse IP %s", ErrFileParse, errUnknownAddressFamily, hexIP)
	}
}

// parseNetIPSocketLine parses a single line, represented by a list of fields.
// It never returns a partially populated socket line: any failure yields a nil
// line together with a categorized error, so callers cannot accidentally
// consume zero-valued socket data.
func parseNetIPSocketLine(fields []string, isUDP bool) (*netIPSocketLine, error) {
	// TCP lines carry 10 required fields, UDP lines additionally carry the
	// drops field at index 12.
	minFields := 10
	if isUDP {
		minFields = 13
	}
	if len(fields) < minFields {
		return nil, fmt.Errorf(
			"%w: %w: less than %d columns found %q",
			ErrFileParse,
			errNetIPSocketFieldCount,
			minFields,
			strings.Join(fields, " "),
		)
	}
	line := &netIPSocketLine{}
	var err error // parse error

	// sl
	s := strings.Split(fields[0], ":")
	if len(s) != 2 {
		return nil, fmt.Errorf("%w: Unable to parse sl field in line %q", ErrFileParse, fields[0])
	}

	if line.Sl, err = strconv.ParseUint(s[0], 0, 64); err != nil {
		return nil, fmt.Errorf("%w: Unable to parse sl field in %q: %w", ErrFileParse, s[0], err)
	}
	// local_address
	l := strings.Split(fields[1], ":")
	if len(l) != 2 {
		return nil, fmt.Errorf("%w: Unable to parse local_address field in %q", ErrFileParse, fields[1])
	}
	if line.LocalAddr, err = parseIP(l[0]); err != nil {
		return nil, err
	}
	if line.LocalPort, err = strconv.ParseUint(l[1], 16, 64); err != nil {
		return nil, fmt.Errorf("%w: Unable to parse local_address port value line %q: %w", ErrFileParse, l[1], err)
	}

	// remote_address
	r := strings.Split(fields[2], ":")
	if len(r) != 2 {
		return nil, fmt.Errorf("%w: Unable to parse rem_address field in %q", ErrFileParse, fields[1])
	}
	if line.RemAddr, err = parseIP(r[0]); err != nil {
		return nil, err
	}
	if line.RemPort, err = strconv.ParseUint(r[1], 16, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse rem_address port value in %q: %w", ErrFileParse, r[1], err)
	}

	// st
	if line.St, err = strconv.ParseUint(fields[3], 16, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse st value in %q: %w", ErrFileParse, fields[3], err)
	}

	// tx_queue and rx_queue
	q := strings.Split(fields[4], ":")
	if len(q) != 2 {
		return nil, fmt.Errorf(
			"%w: Missing colon for tx/rx queues in socket line %q",
			ErrFileParse,
			fields[4],
		)
	}
	if line.TxQueue, err = strconv.ParseUint(q[0], 16, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse tx_queue value in %q: %w", ErrFileParse, q[0], err)
	}
	if line.RxQueue, err = strconv.ParseUint(q[1], 16, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse trx_queue value in %q: %w", ErrFileParse, q[1], err)
	}

	// uid
	if line.UID, err = strconv.ParseUint(fields[7], 0, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse UID value in %q: %w", ErrFileParse, fields[7], err)
	}

	// inode
	if line.Inode, err = strconv.ParseUint(fields[9], 0, 64); err != nil {
		return nil, fmt.Errorf("%w: Cannot parse inode value in %q: %w", ErrFileParse, fields[9], err)
	}

	// drops
	if isUDP {
		drops, err := strconv.ParseUint(fields[12], 0, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: Cannot parse drops value in %q: %w", ErrFileParse, fields[12], err)
		}
		line.Drops = &drops
	}

	return line, nil
}
