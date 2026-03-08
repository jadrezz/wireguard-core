package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

type check struct {
	name string
	fn   func() error
}

func Preflight(configDir string) error {
	checks := []check{
		{"root privileges", checkRoot},
		{"wg", checkCmd("wg")},
		{"wg-quick", checkCmd("wg-quick")},
		{"iptables", checkCmd("iptables")},
		{"ip", checkCmd("ip")},
		{"config directory " + configDir, checkDirWritable(configDir)},
	}

	var errs []string
	for _, c := range checks {
		if err := c.fn(); err != nil {
			errs = append(errs, fmt.Sprintf("  %s: %v", c.name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("preflight checks failed:\n%s", strings.Join(errs, "\n"))
	}
	return nil
}

func checkRoot() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root (current uid=%d)", os.Getuid())
	}
	return nil
}

func checkCmd(name string) func() error {
	return func() error {
		path, err := exec.LookPath(name)
		if err != nil {
			return fmt.Errorf("%q not found in PATH", name)
		}
		_ = path
		return nil
	}
}

func checkDirWritable(dir string) func() error {
	return func() error {
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("directory does not exist")
			}
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory")
		}
		if err := unix.Access(dir, unix.W_OK); err != nil {
			return fmt.Errorf("directory is not writable")
		}
		return nil
	}
}

