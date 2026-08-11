package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDesktopControlClockProductionIgnoresTestFile(t *testing.T) {
	start := time.Now().UTC()
	t.Setenv(desktopControlClockEnvironmentKey, filepath.Join(t.TempDir(), "missing-clock"))

	clock, err := desktopControlClockFromEnvironment("production", os.LookupEnv, start)
	if err != nil {
		t.Fatalf("desktopControlClockFromEnvironment() error = %v", err)
	}
	before := time.Now().UTC()
	got := clock()
	after := time.Now().UTC()
	if got.Before(before) || got.After(after) {
		t.Fatalf("production clock = %s, want real time in [%s, %s]", got, before, after)
	}
}

func TestDesktopControlClockRejectsUnsafeTestFiles(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)

	t.Run("relative path", func(t *testing.T) {
		t.Setenv(desktopControlClockEnvironmentKey, "clock.txt")
		if _, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start); err == nil {
			t.Fatal("relative test clock path was accepted")
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := t.TempDir()
		t.Setenv(desktopControlClockEnvironmentKey, path)
		if _, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start); err == nil {
			t.Fatal("directory test clock was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "clock-target")
		writeDesktopControlClock(t, target, start, 0o600)
		path := filepath.Join(root, "clock-link")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		t.Setenv(desktopControlClockEnvironmentKey, path)
		if _, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start); err == nil {
			t.Fatal("symlink test clock was accepted")
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("group-readable mode", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clock")
			writeDesktopControlClock(t, path, start, 0o640)
			t.Setenv(desktopControlClockEnvironmentKey, path)
			if _, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start); err == nil {
				t.Fatal("non-owner-only test clock was accepted")
			}
		})
	}
}

func TestDesktopControlClockAdvancesAndFallsBackToRealTime(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "clock")
	writeDesktopControlClock(t, path, start, 0o600)
	t.Setenv(desktopControlClockEnvironmentKey, path)

	clock, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start)
	if err != nil {
		t.Fatalf("desktopControlClockFromEnvironment() error = %v", err)
	}
	if got := clock(); !got.Equal(start) {
		t.Fatalf("initial clock = %s, want %s", got, start)
	}

	advanced := start.Add(151 * time.Second)
	writeDesktopControlClock(t, path, advanced, 0o600)
	if got := clock(); !got.Equal(advanced) {
		t.Fatalf("advanced clock = %s, want %s", got, advanced)
	}

	for name, contents := range map[string]string{
		"malformed":      "not-a-time\n",
		"regressing":     start.Add(30*time.Second).Format(time.RFC3339Nano) + "\n",
		"outside window": start.Add(25*time.Hour).Format(time.RFC3339Nano) + "\n",
		"oversized":      string(make([]byte, 129)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			before := time.Now().UTC()
			got := clock()
			after := time.Now().UTC()
			if got.Before(before) || got.After(after) {
				t.Fatalf("fallback clock = %s, want real time in [%s, %s]", got, before, after)
			}
		})
	}
}

func TestDesktopControlClockTestEnvironmentWithoutFileUsesRealTime(t *testing.T) {
	start := time.Now().UTC()
	t.Setenv(desktopControlClockEnvironmentKey, "")
	clock, err := desktopControlClockFromEnvironment("test", os.LookupEnv, start)
	if err != nil {
		t.Fatalf("desktopControlClockFromEnvironment() error = %v", err)
	}
	before := time.Now().UTC()
	got := clock()
	after := time.Now().UTC()
	if got.Before(before) || got.After(after) {
		t.Fatalf("default test clock = %s, want real time in [%s, %s]", got, before, after)
	}
}

func writeDesktopControlClock(t *testing.T, path string, value time.Time, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value.UTC().Format(time.RFC3339Nano)+"\n"), mode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
}
