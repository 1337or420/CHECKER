//go:build windows

package procx

import "os/exec"

// SetPgid — no-op на Windows. Реальный target — Linux-контейнер.
func SetPgid(cmd *exec.Cmd) {}

// KillGroup — no-op. На Windows используем cmd.Process.Kill() вручную.
func KillGroup(pid int) {}

// TermGroup — no-op.
func TermGroup(pid int) {}