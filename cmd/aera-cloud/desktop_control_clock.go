package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bignormal/aera-cloud/internal/config"
)

const (
	desktopControlClockEnvironmentKey = "AGENTERA_CLOUD_DESKTOP_CONTROL_TEST_CLOCK_FILE"
	desktopControlClockMaxBytes       = 128
	desktopControlClockWindow         = 24 * time.Hour
)

// desktopControlClockFromEnvironment is deliberately composed in the binary
// entrypoint rather than exposed over HTTP. Production and non-test
// environments always use the real wall clock, even if a test variable leaks
// into the process environment.
func desktopControlClockFromEnvironment(
	environment string,
	lookup config.LookupEnv,
	processStart time.Time,
) (func() time.Time, error) {
	realClock := func() time.Time { return time.Now().UTC() }
	if environment != "test" {
		return realClock, nil
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	path, ok := lookup(desktopControlClockEnvironmentKey)
	path = strings.TrimSpace(path)
	if !ok || path == "" {
		return realClock, nil
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("desktop control test clock path must be absolute")
	}
	if err := validateDesktopControlClockPath(path); err != nil {
		return nil, err
	}

	start := processStart.UTC()
	var mu sync.Mutex
	var last time.Time
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		value, ok := readDesktopControlClock(path, start)
		if !ok || (!last.IsZero() && value.Before(last)) {
			return realClock()
		}
		last = value
		return value
	}, nil
}

func validateDesktopControlClockPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("desktop control test clock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("desktop control test clock must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("desktop control test clock must be owner-only (0600)")
	}
	return nil
}

func readDesktopControlClock(path string, processStart time.Time) (time.Time, bool) {
	file, err := os.Open(path)
	if err != nil {
		return time.Time{}, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return time.Time{}, false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return time.Time{}, false
	}
	contents, err := io.ReadAll(io.LimitReader(file, desktopControlClockMaxBytes+1))
	if err != nil || len(contents) > desktopControlClockMaxBytes {
		return time.Time{}, false
	}
	value, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(contents)))
	if err != nil {
		return time.Time{}, false
	}
	value = value.UTC()
	if value.Before(processStart.Add(-desktopControlClockWindow)) || value.After(processStart.Add(desktopControlClockWindow)) {
		return time.Time{}, false
	}
	return value, true
}
