package utils

import (
	"fmt"
	"os"
	"strings"
	"strconv"
	"syscall"
	"time"
)

func FindFirstPIDByPS(cmdline...string) (int, error) {
	return FindFirstPIDByPSExtern(false, cmdline...)
}

func FindFirstPIDByPSExtern(non_sudo bool, cmdline...string) (int, error) {
	Assert(cmdline != nil, "cmdline must have one parameter at least")

	cmds := []string {"ps aux"}
	for _, c := range cmdline {
		cmds = append(cmds, fmt.Sprintf("grep '%s'", "[" + c[0:1] + "]" + c[1:]))
	}
	if non_sudo {
		cmds = append(cmds, "grep -v ' sudo '")
	}
	cmds = append(cmds, "awk '{print $2; exit}'")

	b := Bash{
		Command: strings.Join(cmds, " | "),
		NoLog: true,
	}

	ret, o, _, err := b.RunWithReturn()
	if err != nil {
		return -2, err
	}

	o = strings.TrimSpace(o)
	if ret != 0 || o == "" {
		return -1, fmt.Errorf("cannot find any process having command line%v", cmdline)
	}

	return strconv.Atoi(o)
}


func KillProcess(pid int) error {
	return KillProcess1(pid, 15)
}

func KillProcess1(pid int, waitTime uint) error {
	b := Bash{
		Command: fmt.Sprintf("sudo kill %v", pid),
	}
	b.Run()

	check := func() bool {
		// return true if process not exists
		return ProcessExists(pid) != nil
	}

	if check() {
		return nil
	}

	return LoopRunUntilSuccessOrTimeout(func() bool {
		b := Bash{
			Command: fmt.Sprintf("sudo kill -9 %v", pid),
		}
		b.Run()

		return check()
	}, time.Duration(waitTime) * time.Second, time.Duration(500) * time.Millisecond)
}


func ProcessExists(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	if err = process.Signal(syscall.Signal(0)); err == nil {
		return nil
	}

	if err == syscall.EPERM {
		return nil
	}

	return err

}
