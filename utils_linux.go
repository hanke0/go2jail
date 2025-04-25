//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func init() {
	setCmdUserAndGroup = setCmdUserAndGroupLinux
}

func setCmdUserAndGroupLinux(cmd *exec.Cmd, username, group string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("bad uid: %s", u.Uid)
	}
	var gid uint64
	if group == "" {
		gid, err = strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("bad gid: %s", u.Gid)
		}
	} else {
		g, err := user.LookupGroup(group)
		if err != nil {
			return err
		}
		gid, err = strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("bad gid: %s", g.Gid)
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if cmd.SysProcAttr.Credential == nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{}
	}
	cmd.SysProcAttr.Credential.Uid = uint32(uid)
	cmd.SysProcAttr.Credential.Gid = uint32(gid)
	return nil
}
