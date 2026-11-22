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
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// For the proc file format details,
// see https://elixir.bootlin.com/linux/v4.17/source/net/unix/af_unix.c#L2815
// and https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/net.h#L48.

// Constants for the various /proc/net/unix enumerations.
// TODO: match against x/sys/unix or similar?
const (
	netUnixTypeStream    = 1
	netUnixTypeDgram     = 2
	netUnixTypeSeqpacket = 5

	netUnixFlagDefault = 0
	netUnixFlagListen  = 1 << 16

	netUnixStateUnconnected  = 1
	netUnixStateConnecting   = 2
	netUnixStateConnected    = 3
	netUnixStateDisconnected = 4
)

// NetUNIXType is the type of the type field.
type NetUNIXType uint64

// NetUNIXFlags is the type of the flags field.
type NetUNIXFlags uint64

// NetUNIXState is the type of the state field.
type NetUNIXState uint64

// Categories of per-line parse failures reported by the tolerant UNIX socket
// table parser.
const (
	// NetUNIXErrorFieldCount means a line does not carry the expected minimum
	// number of fields.
	NetUNIXErrorFieldCount = "field count mismatch"
	// NetUNIXErrorField means one of the present fields cannot be parsed.
	NetUNIXErrorField = "malformed field"
)

// NetUNIXLine represents a line of /proc/net/unix.
type NetUNIXLine struct {
	KernelPtr string
	RefCount  uint64
	Protocol  uint64
	Flags     NetUNIXFlags
	Type      NetUNIXType
	State     NetUNIXState
	Inode     uint64
	Path      string
}

// NetUNIX holds the data read from /proc/net/unix.
type NetUNIX struct {
	Rows []*NetUNIXLine
}

// errNetUNIXFieldCount marks a line carrying fewer fields than the parser
// needs.
var errNetUNIXFieldCount = errors.New("unexpected number of fields")

// NetUNIXLineError describes a single line that could not be parsed.
// Line numbers are 1-based and include the header line, matching the line
// numbers seen when opening the kernel file directly.
type NetUNIXLineError struct {
	// Line is the 1-based line number within the source file.
	Line int
	// Category classifies the failure, see the NetUNIXError* constants.
	Category string
	// Err is the underlying parse error.
	Err error
}

func (e NetUNIXLineError) Error() string {
	return fmt.Sprintf("%s: line %d: %s: %s", ErrFileParse, e.Line, e.Category, e.Err)
}

// Unwrap exposes both the parser sentinel and the underlying line error so
// errors.Is matches either.
func (e NetUNIXLineError) Unwrap() []error {
	return []error{ErrFileParse, e.Err}
}

// NetUNIXPartialResult is the tolerant parsing result of a /proc/net/unix
// file. Valid lines are kept in Rows while every rejected line is recorded in
// LineErrors together with its line number and failure category.
type NetUNIXPartialResult struct {
	// Rows contains the successfully parsed lines in kernel file order.
	Rows []*NetUNIXLine
	// LineErrors records the rejected lines with their line numbers.
	LineErrors []NetUNIXLineError
}

// Complete reports whether the file was parsed without any rejected line.
func (r NetUNIXPartialResult) Complete() bool {
	return len(r.LineErrors) == 0
}

// NetUNIX returns data read from /proc/net/unix.
func (fs FS) NetUNIX() (*NetUNIX, error) {
	return readNetUNIX(fs.proc.Path("net/unix"))
}

// NetUNIXPartial returns data read from /proc/net/unix without failing on
// individual malformed lines. Successfully parsed lines are returned in kernel
// file order and every rejected line is reported with its line number and
// failure category. Use the result's Complete method to check whether the whole
// file was parsed successfully.
func (fs FS) NetUNIXPartial() (NetUNIXPartialResult, error) {
	return readNetUNIXPartial(fs.proc.Path("net/unix"))
}

// readNetUNIX reads data in /proc/net/unix format from the specified file.
func readNetUNIX(file string) (*NetUNIX, error) {
	// This file could be quite large and a streaming read is desirable versus
	// reading the entire contents at once.
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseNetUNIX(f)
}

// readNetUNIXPartial reads data in /proc/net/unix format from the specified
// file, keeping valid lines and recording rejected ones instead of failing the
// whole table.
func readNetUNIXPartial(file string) (NetUNIXPartialResult, error) {
	f, err := os.Open(file)
	if err != nil {
		return NetUNIXPartialResult{}, err
	}
	defer f.Close()

	return parseNetUNIXPartial(f)
}

// parseNetUNIX creates a NetUnix structure from the incoming stream.
func parseNetUNIX(r io.Reader) (*NetUNIX, error) {
	result, err := parseNetUNIXPartial(r)
	if err != nil {
		return nil, err
	}
	if len(result.LineErrors) > 0 {
		// Keep the historical strict contract: surface the first bad line.
		return nil, result.LineErrors[0]
	}

	return &NetUNIX{Rows: result.Rows}, nil
}

// parseNetUNIXPartial scans the stream line by line. The scanner is local to
// this call, so concurrent parses never share mutable state. Rows keep the
// kernel file order.
func parseNetUNIXPartial(r io.Reader) (NetUNIXPartialResult, error) {
	// Begin scanning by checking for the existence of Inode.
	s := bufio.NewScanner(r)
	s.Scan()

	// From the man page of proc(5), it does not contain an Inode field,
	// but in actually it exists. This code works for both cases.
	hasInode := strings.Contains(s.Text(), "Inode")

	// Expect a minimum number of fields, but Inode and Path are optional:
	// Num       RefCount Protocol Flags    Type St Inode Path
	minFields := 6
	if hasInode {
		minFields++
	}

	var result NetUNIXPartialResult
	lineNo := 1 // the header line consumed above
	for s.Scan() {
		lineNo++
		item, err := parseNetUNIXLine(s.Text(), hasInode, minFields)
		if err != nil {
			category := NetUNIXErrorField
			if errors.Is(err, errNetUNIXFieldCount) {
				category = NetUNIXErrorFieldCount
			}
			result.LineErrors = append(result.LineErrors, NetUNIXLineError{
				Line:     lineNo,
				Category: category,
				Err:      err,
			})
			continue
		}

		result.Rows = append(result.Rows, item)
	}

	if err := s.Err(); err != nil {
		return NetUNIXPartialResult{}, fmt.Errorf("%w: /proc/net/unix encountered data: %w", ErrFileParse, err)
	}

	return result, nil
}

func parseNetUNIXLine(line string, hasInode bool, minFields int) (*NetUNIXLine, error) {
	fields := strings.Fields(line)

	l := len(fields)
	if l < minFields {
		return nil, fmt.Errorf("%w: %w: expected at least %d fields but got %d", ErrFileParse, errNetUNIXFieldCount, minFields, l)
	}

	// Field offsets are as follows:
	// Num       RefCount Protocol Flags    Type St Inode Path

	kernelPtr := strings.TrimSuffix(fields[0], ":")

	users, err := parseNetUNIXUsers(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: ref count %q: %w", ErrFileParse, fields[1], err)
	}

	flags, err := parseNetUNIXFlags(fields[3])
	if err != nil {
		return nil, fmt.Errorf("%w: Unable to parse flags %q: %w", ErrFileParse, fields[3], err)
	}

	typ, err := parseNetUNIXType(fields[4])
	if err != nil {
		return nil, fmt.Errorf("%w: Failed to parse type %q: %w", ErrFileParse, fields[4], err)
	}

	state, err := parseNetUNIXState(fields[5])
	if err != nil {
		return nil, fmt.Errorf("%w: Failed to parse state %q: %w", ErrFileParse, fields[5], err)
	}

	var inode uint64
	if hasInode {
		inode, err = parseNetUNIXInode(fields[6])
		if err != nil {
			return nil, fmt.Errorf("%w failed to parse inode %q: %w", ErrFileParse, fields[6], err)
		}
	}

	n := &NetUNIXLine{
		KernelPtr: kernelPtr,
		RefCount:  users,
		Type:      typ,
		Flags:     flags,
		State:     state,
		Inode:     inode,
	}

	// Path field is optional.
	if l > minFields {
		// Path occurs at either index 6 or 7 depending on whether inode is
		// already present.
		pathIdx := 7
		if !hasInode {
			pathIdx--
		}

		n.Path = fields[pathIdx]
	}

	return n, nil
}

func parseNetUNIXUsers(s string) (uint64, error) {
	return strconv.ParseUint(s, 16, 32)
}

func parseNetUNIXType(s string) (NetUNIXType, error) {
	typ, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, err
	}

	return NetUNIXType(typ), nil
}

func parseNetUNIXFlags(s string) (NetUNIXFlags, error) {
	flags, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}

	return NetUNIXFlags(flags), nil
}

func parseNetUNIXState(s string) (NetUNIXState, error) {
	st, err := strconv.ParseInt(s, 16, 8)
	if err != nil {
		return 0, err
	}

	return NetUNIXState(st), nil
}

func parseNetUNIXInode(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

func (t NetUNIXType) String() string {
	switch t {
	case netUnixTypeStream:
		return "stream"
	case netUnixTypeDgram:
		return "dgram"
	case netUnixTypeSeqpacket:
		return "seqpacket"
	}
	return "unknown"
}

func (f NetUNIXFlags) String() string {
	switch f {
	case netUnixFlagListen:
		return "listen"
	default:
		return "default"
	}
}

func (s NetUNIXState) String() string {
	switch s {
	case netUnixStateUnconnected:
		return "unconnected"
	case netUnixStateConnecting:
		return "connecting"
	case netUnixStateConnected:
		return "connected"
	case netUnixStateDisconnected:
		return "disconnected"
	}
	return "unknown"
}
