//go:build !unix

package assistant

import "os/exec"

func ownProcessGroup(cmd *exec.Cmd) {}
