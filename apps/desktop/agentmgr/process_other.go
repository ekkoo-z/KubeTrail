//go:build !windows

package agentmgr

import "os/exec"

func configureAgentCommand(cmd *exec.Cmd) {}
