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
	"strings"

	"github.com/prometheus/procfs/internal/parsers"
)

// Deterministic outcomes for cgroup view resolution and stat reads. In mixed
// cgroup v1/v2 environments a process may move between hierarchies (container
// migration) or exit while its statistics are being read. These sentinel
// errors give callers a stable, retryable boundary instead of partial or
// mis-attributed data.
var (
	// ErrControllerUnsupported is returned when a controller name is not a
	// known cgroup v1 or v2 controller, or when the controller is known but
	// has no hierarchy in the process's own cgroup view. Unknown controllers
	// are never merged into another controller's statistics.
	ErrControllerUnsupported = errors.New("cgroup controller not supported")
	// ErrCgroupMoved is returned when the resolved cgroup path keeps
	// disappearing across all retries, i.e. the process was migrated to a
	// different cgroup while being read.
	ErrCgroupMoved = errors.New("cgroup path moved or vanished during read")
	// ErrCgroupProcessGone is returned when the process exits while its
	// cgroup files are being read.
	ErrCgroupProcessGone = errors.New("process exited during cgroup read")
)

// cgroupStatRetries is the default number of retries after the initial read
// before a missing cgroup file is reported as ErrCgroupMoved.
const cgroupStatRetries = 3

// knownV1Controllers are the controllers that may appear on cgroup v1
// hierarchies.
var knownV1Controllers = map[string]struct{}{
	"blkio":      {},
	"cpu":        {},
	"cpuacct":    {},
	"cpuset":     {},
	"debug":      {},
	"devices":    {},
	"freezer":    {},
	"hugetlb":    {},
	"memory":     {},
	"misc":       {},
	"net_cls":    {},
	"net_prio":   {},
	"perf_event": {},
	"pids":       {},
	"rdma":       {},
}

// knownV2Controllers are the controllers that may appear on the unified
// cgroup v2 hierarchy.
var knownV2Controllers = map[string]struct{}{
	"cpu":     {},
	"cpuset":  {},
	"dmem":    {},
	"hugetlb": {},
	"io":      {},
	"memory":  {},
	"misc":    {},
	"pids":    {},
	"rdma":    {},
}

// supportedController reports whether name is a known cgroup v1 or v2
// controller. Named v1 hierarchies ("name=systemd") are also supported.
func supportedController(name string) bool {
	if _, ok := knownV1Controllers[name]; ok {
		return true
	}
	if _, ok := knownV2Controllers[name]; ok {
		return true
	}
	return strings.HasPrefix(name, "name=")
}

// CgroupView is a consistent snapshot of one process's placement in every
// cgroup hierarchy on the system, taken from a single read of
// /proc/<pid>/cgroup. Every entry keeps its hierarchy ID, its full controller
// list and its full path relative to the hierarchy's mount point; paths are
// never reduced to their last segment.
type CgroupView struct {
	// PID is the process this view belongs to. All resource statistics
	// resolved through this view come from this single process identity.
	PID int
	// Entries holds one Cgroup per hierarchy (v1) plus the unified v2
	// hierarchy, exactly as parsed from /proc/<pid>/cgroup.
	Entries []Cgroup

	// procPath is the /proc/<pid> directory used to detect process exit
	// during stat reads. It is empty for views built by parseCgroupView.
	procPath string
}

// parseCgroupView builds a CgroupView for pid from the contents of
// /proc/<pid>/cgroup.
func parseCgroupView(pid int, data []byte) (*CgroupView, error) {
	entries, err := parseCgroups(data)
	if err != nil {
		return nil, err
	}
	return &CgroupView{PID: pid, Entries: entries}, nil
}

// CgroupView reads /proc/<pid>/cgroup once and returns the resulting
// snapshot. If the process has already exited, ErrCgroupProcessGone is
// returned.
func (p Proc) CgroupView() (*CgroupView, error) {
	data, err := parsers.ReadFileNoStat(p.path("cgroup"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: pid %d", ErrCgroupProcessGone, p.PID)
		}
		return nil, err
	}
	view, err := parseCgroupView(p.PID, data)
	if err != nil {
		return nil, err
	}
	view.procPath = p.path()
	return view, nil
}

// Version reports whether this entry belongs to a cgroup v1 hierarchy (1) or
// the unified cgroup v2 hierarchy (2).
func (c Cgroup) Version() int {
	if c.HierarchyID == 0 && len(c.Controllers) == 0 {
		return 2
	}
	return 1
}

// Entry returns the view entry governing the given controller. A controller
// that is unknown, or known but not bound to any hierarchy in this view, is
// reported as ErrControllerUnsupported; it is never silently attributed to
// another controller's hierarchy.
func (v CgroupView) Entry(controller string) (Cgroup, error) {
	if !supportedController(controller) {
		return Cgroup{}, fmt.Errorf("%w: %q", ErrControllerUnsupported, controller)
	}
	for _, e := range v.Entries {
		if e.Version() == 2 {
			if _, ok := knownV2Controllers[controller]; ok {
				return e, nil
			}
			continue
		}
		for _, c := range e.Controllers {
			if c == controller {
				return e, nil
			}
		}
	}
	return Cgroup{}, fmt.Errorf("%w: %q: no hierarchy in view for pid %d", ErrControllerUnsupported, controller, v.PID)
}

// resolveCgroupMount finds the mount point of the hierarchy described by e
// among mounts. For v1 the mount's super options must list the requested
// controller; for v2 the single cgroup2 mount is used.
func resolveCgroupMount(mounts []*MountInfo, e Cgroup, controller string) (string, error) {
	for _, m := range mounts {
		switch m.FSType {
		case "cgroup2":
			if e.Version() == 2 {
				return m.MountPoint, nil
			}
		case "cgroup":
			if e.Version() != 1 {
				continue
			}
			if _, ok := m.SuperOptions[controller]; ok {
				return m.MountPoint, nil
			}
		}
	}
	return "", fmt.Errorf("%w: no cgroup mount for controller %q", ErrMountPoint, controller)
}

// StatPath resolves the absolute path of the cgroup pseudo-file name for the
// given controller, using this view and the process's own mount table. The
// full relative path of the hierarchy entry is preserved when joining; it is
// never reduced to its last segment.
func (v CgroupView) StatPath(mounts []*MountInfo, controller, name string) (string, error) {
	e, err := v.Entry(controller)
	if err != nil {
		return "", err
	}
	mountPoint, err := resolveCgroupMount(mounts, e, controller)
	if err != nil {
		return "", err
	}
	return filepath.Join(mountPoint, e.Path, name), nil
}

// readCgroupFile reads one cgroup pseudo-file with bounded retries. A file
// that vanishes (container migration) is retried up to retries times; if the
// process exits in the meantime ErrCgroupProcessGone is returned, and if the
// path is still missing after all retries ErrCgroupMoved is returned. Any
// other read error is returned as-is. procAlive may be nil to skip the
// liveness check.
func readCgroupFile(path string, procAlive func() bool, retries int, read func(string) ([]byte, error)) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, err := read(path)
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		if procAlive != nil && !procAlive() {
			return nil, fmt.Errorf("%w: %s", ErrCgroupProcessGone, path)
		}
		if attempt >= retries {
			return nil, fmt.Errorf("%w: %s", ErrCgroupMoved, path)
		}
	}
}

// CgroupStatReader reads resource statistics for one process from one
// consistent CgroupView, so v1 and v2 statistics always come from the same
// process identity and the same cgroup view. Transient races with container
// migration and process exit are retried and then reported as deterministic
// sentinel errors.
type CgroupStatReader struct {
	// View is the cgroup membership snapshot all reads are resolved against.
	View *CgroupView
	// Mounts is the mount table of the same process, used to locate each
	// hierarchy's mount point.
	Mounts []*MountInfo
	// Retries bounds how often a vanished cgroup file is re-read before
	// ErrCgroupMoved is returned. Zero uses cgroupStatRetries.
	Retries int
}

// CgroupStatReader returns a reader bound to the process pid: its cgroup
// view and its mount table are both taken from that single process.
func (fs FS) CgroupStatReader(pid int) (*CgroupStatReader, error) {
	p, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}
	view, err := p.CgroupView()
	if err != nil {
		return nil, err
	}
	mounts, err := p.MountInfo()
	if err != nil {
		return nil, err
	}
	return &CgroupStatReader{View: view, Mounts: mounts, Retries: cgroupStatRetries}, nil
}

// ReadFile reads the cgroup pseudo-file name for controller from the
// hierarchy this process belongs to. Unknown controllers return
// ErrControllerUnsupported; migration and process exit return ErrCgroupMoved
// and ErrCgroupProcessGone after the configured retries.
func (r CgroupStatReader) ReadFile(controller, name string) ([]byte, error) {
	path, err := r.View.StatPath(r.Mounts, controller, name)
	if err != nil {
		return nil, err
	}
	retries := r.Retries
	if retries < 0 {
		retries = 0
	}
	var procAlive func() bool
	if r.View.procPath != "" {
		procAlive = func() bool {
			_, err := os.Stat(r.View.procPath)
			return err == nil
		}
	}
	return readCgroupFile(path, procAlive, retries, parsers.ReadFileNoStat)
}
