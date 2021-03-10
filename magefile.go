// +build mage

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
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
	ModMode = "-mod=vendor"
)

// Build builds the library.
func Build() error {
	fmt.Println("Building...")
	return sh.Run(Go, "build", ModMode, "./...")
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
	args = append(args, ModMode, "-race", "-tags", "unit")
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

// Packr generates go files for static resources. Generated files should be committed into source control in order to
// remove any dependency on the Packr tool in consumers of this library.  This is intended to be called by developers,
// not the build tool.
func Packr() error {
	mg.Deps(ensureGobin)
	return gobinRun("github.com/gobuffalo/packr/packr")
}

// PackrClean deletes all the packr generated go files.
func PackrClean() error {
	mg.Deps(ensureGobin)
	return gobinRun("github.com/gobuffalo/packr/packr", "clean")
}

func ensureGobin() error {
	return installIfNotPresent("gobin", "github.com/myitcv/gobin")
}

func gobinRun(cmd string, args ...string) error {
	return sh.Run(findOnPathOrGoPath("gobin"), append([]string{"-m", "-run", cmd},
		args...)...)
}

// InstallIfNotPresent installs a go based tool (if not already installed)
func installIfNotPresent(execName, goPackage string) error {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
		return err
	}
	pathOfExec := findOnPathOrGoPath(execName)
	if len(pathOfExec) == 0 {
		cmd := exec.Command(Go, "get", "-u", goPackage)
		cmd.Dir = usr.HomeDir
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Wait()
	}
	return nil
}

func findOnPathOrGoPath(execName string) string {
	if p := findOnPath(execName); p != "" {
		return p
	}
	p := filepath.Join(goPath(), "bin", execName)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	fmt.Printf("Could not find %s on PATH or in GOPATH/bin\n", execName)
	return ""
}

func findOnPath(execName string) string {
	pathEnv := os.Getenv("PATH")
	pathDirectories := strings.Split(pathEnv, string(os.PathListSeparator))
	for _, pathDirectory := range pathDirectories {
		possible := filepath.Join(pathDirectory, execName)
		stat, err := os.Stat(possible)
		if err == nil || os.IsExist(err) {
			if (stat.Mode() & 0111) != 0 {
				return possible
			}
		}
	}
	return ""
}

func goPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	goPath, goPathSet := os.LookupEnv("GOPATH")
	if !goPathSet {
		goPath = filepath.Join(usr.HomeDir, Go)
	}
	return goPath
}
