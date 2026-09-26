//go:build unix

package assistant

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup runs the CLI in its own process group and, at the
// deadline, kills the group: Claude Code starts helpers (the MCP server,
// among them) that would otherwise keep its pipes open after it is gone.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
