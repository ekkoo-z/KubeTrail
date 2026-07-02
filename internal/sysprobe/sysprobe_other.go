//go:build !linux

package sysprobe

import "time"

func ProbeNames() []string {
	return []string{"unsupported"}
}

func RunOne(name string) Result {
	start := time.Now()
	return Result{
		Name:     name,
		Allowed:  false,
		Error:    "syscall probing is only implemented on linux",
		Duration: time.Since(start).Milliseconds(),
	}
}
