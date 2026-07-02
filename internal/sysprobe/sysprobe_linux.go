//go:build linux

package sysprobe

import (
	"syscall"
	"time"
)

func ProbeNames() []string {
	return []string{
		"getpid",
		"getppid",
		"getuid",
		"geteuid",
		"getgid",
		"getegid",
		"uname",
		"keyctl",
		"perf_event_open",
		"mount",
	}
}

func RunOne(name string) Result {
	start := time.Now()
	result := Result{Name: name}
	var errno syscall.Errno

	switch name {
	case "getpid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	case "getppid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0)
	case "getuid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETUID, 0, 0, 0)
	case "geteuid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETEUID, 0, 0, 0)
	case "getgid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETGID, 0, 0, 0)
	case "getegid":
		_, _, errno = syscall.RawSyscall(syscall.SYS_GETEGID, 0, 0, 0)
	case "uname":
		var uts syscall.Utsname
		err := syscall.Uname(&uts)
		if err != nil {
			errno = err.(syscall.Errno)
		}
	case "keyctl":
		_, _, errno = syscall.RawSyscall(syscall.SYS_KEYCTL, 0, 0, 0)
	case "perf_event_open":
		_, _, errno = syscall.RawSyscall6(syscall.SYS_PERF_EVENT_OPEN, 0, 0, 0, 0, 0, 0)
	case "mount":
		_, _, errno = syscall.RawSyscall6(syscall.SYS_MOUNT, 0, 0, 0, 0, 0, 0)
	default:
		result.Error = "unknown syscall probe"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	result.Allowed = errno == 0
	if errno != 0 {
		result.Errno = errno.Error()
	}
	result.Duration = time.Since(start).Milliseconds()
	return result
}
