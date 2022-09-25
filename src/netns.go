package higgs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"sync"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// NewNetns creates and returns named network namespace,
// or the current namespace if no name is specified
func NewNetns(name string) (netns.NsHandle, error) {
	// shortcut for current namespace
	if name == "" {
		return netns.Get()
	}

	// for sinners
	if pid, err := strconv.Atoi(name); err == nil {
		return netns.GetFromPid(pid)
	}

	// shortcut for existing namespace
	ns, err := netns.GetFromName(name)
	if err == nil {
		return ns, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("unexpected error when getting netns handle %s: %s", name, err)
	}

	// create the runtime dir if it does not exist
	// also try to replicate the behavior of iproute2 by mounting tmpfs onto it
	const runtimeDir = "/run/netns"
	_, err = os.Stat(runtimeDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("unexpected error when stating runtime dir %s: %s", runtimeDir, err)
		}
		err = os.MkdirAll(runtimeDir, 0755)
		if err != nil {
			return 0, fmt.Errorf("failed to create runtime dir %s: %s", runtimeDir, err)
		}
		err = unix.Mount("tmpfs", runtimeDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=755")
		if err != nil {
			return 0, fmt.Errorf("failed to mount tmpfs onto runtime dir %s: %s", runtimeDir, err)
		}
		zap.S().Debugf("created netns runtime dir: %s", runtimeDir)
	}

	// create the fd for the new namespace
	var nsPath = path.Join(runtimeDir, name)
	nsFd, err := os.Create(nsPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create ns fd %s: %s", nsPath, err)
	}
	err = nsFd.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to close ns fd %s: %s", nsPath, err)
	}
	// cleanup the fd file in case of failure
	// this has no effect when the new netns is successfully mounted
	defer os.RemoveAll(nsPath)
	zap.S().Debugf("created netns fd: %s", nsPath)

	// do the dirty jobs in a locked os thread
	// go runtime will reap it instead of reuse it
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		err = unix.Unshare(unix.CLONE_NEWNET)
		if err != nil {
			err = fmt.Errorf("failed to unshare netns: %s", err)
			return
		}
		threadNsPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		err = unix.Mount(threadNsPath, nsPath, "none", unix.MS_BIND|unix.MS_SHARED|unix.MS_REC, "")
		if err != nil {
			err = fmt.Errorf("failed to bind mount nsfs %s: %s", threadNsPath, err)
			return
		}
	}()
	wg.Wait()
	if err != nil {
		return 0, err
	}

	zap.S().Debugf("created namespace: %s", name)
	return netns.GetFromName(name)
}
