//go:build windows

package runtime

import "os"

func terminate(p *os.Process) error { return p.Kill() }
