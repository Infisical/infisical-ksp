//go:build windows

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// The provider runs inside signtool (no console), so it logs to a file from config. Logging is
// discarded until configured.
var (
	logOnce sync.Once
	logger  = log.New(io.Discard, "", log.LstdFlags|log.LUTC)
)

// setupLogging points the logger at the configured file. A bad path falls back to discarding.
func setupLogging(file string) {
	logOnce.Do(func() {
		if file == "" {
			return
		}
		// Create the parent directory so the default path works on a fresh machine.
		_ = os.MkdirAll(filepath.Dir(file), 0o755)
		f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		logger.SetOutput(f)
		logger.SetPrefix("[infisical-ksp] ")
	})
}

// logError logs the failure and, when available, a fix-it hint (signtool only shows a generic
// NTE_* code).
func logError(op string, err error) {
	logger.Printf("ERROR %s: %v", op, err)
	if hint := adviceForError(err); hint != "" {
		logger.Printf("HINT  %s: %s", op, hint)
	}
}
