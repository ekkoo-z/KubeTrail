package agentmgr

import (
	"context"
	"os/exec"
)

func agentCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	configureAgentCommand(cmd)
	return cmd
}
