//go:build !windows

package procx

import (
	"os/exec"
	"syscall"
)

// SetPgid делает процесс лидером своей группы процессов.
// Нужно, чтобы можно было убить всё дерево (nmap -> sh -> ...).
func SetPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// KillGroup убивает всю группу процессов (SIGKILL).
func KillGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// TermGroup мягко завершает группу (SIGTERM).
func TermGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
}