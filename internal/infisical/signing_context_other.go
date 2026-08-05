//go:build !windows

package infisical

import "os"

func processCommandLine() []string {
	return os.Args
}
