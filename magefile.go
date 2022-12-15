//go:build mage

package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"golang.org/x/crypto/ssh/terminal"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
// var Default = Build

const (
	Go = "go"
)

// Build builds the library.
func Build() error {
	fmt.Println("Building...")
	return sh.Run(Go, "build", "./...")
}

// Clean deletes any build artifacts.
func Clean() {
	fmt.Println("Cleaning...")
	os.RemoveAll("bin")
}

// Test runs unit tests without coverage.
// The mage `-v` option will trigger a verbose output of the test
func Test() error {
	return runTests()
}

func runTests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-race", "-tags", "unit")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED":         "1",
		"GO111MODULE":         "on",
		"AWS_SDK_LOAD_CONFIG": "1",
	}
	writer := ColorizeTestStdout()
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func ColorizeTestOutput(w io.Writer) io.Writer {
	writer := NewRegexpWriter(w, `PASS.*`, "\033[32m$0\033[0m")
	return NewRegexpWriter(writer, `FAIL.*`, "\033[31m$0\033[0m")
}

func ColorizeTestStdout() io.Writer {
	if terminal.IsTerminal(syscall.Stdout) {
		return ColorizeTestOutput(os.Stdout)
	}
	return os.Stdout
}

type regexpWriter struct {
	inner io.Writer
	re    *regexp.Regexp
	repl  []byte
}

func NewRegexpWriter(inner io.Writer, re string, repl string) io.Writer {
	return &regexpWriter{inner, regexp.MustCompile(re), []byte(repl)}
}

func (w *regexpWriter) Write(p []byte) (int, error) {
	r := w.re.ReplaceAll(p, w.repl)
	n, err := w.inner.Write(r)
	if n > len(r) {
		n = len(r)
	}
	return n, err
}
