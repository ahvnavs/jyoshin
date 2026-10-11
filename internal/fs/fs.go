// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package fs provides a rooted filesystem abstraction allowing read-only access
// anchored at a specific root (defaulting to "/") for both production execution
// and fixture-tree testing.
package fs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FS defines filesystem inspection operations needed by read-only sensors.
type FS interface {
	// Root returns the configured root path.
	Root() string
	// Path resolves a system path (e.g. "/proc/cpuinfo") relative to the configured root.
	Path(elem ...string) string
	// ReadFile reads the named file relative to Root.
	ReadFile(name string) ([]byte, error)
	// ReadDir reads the named directory relative to Root.
	ReadDir(name string) ([]os.DirEntry, error)
	// Stat returns file info for name relative to Root.
	Stat(name string) (os.FileInfo, error)
	// Readlink returns the destination of the named symbolic link relative to Root.
	Readlink(name string) (string, error)
	// Open opens the named file for reading relative to Root.
	Open(name string) (*os.File, error)
}

// RootedFS implements FS anchored to a root directory.
type RootedFS struct {
	root string
}

// NewRootedFS creates a new RootedFS. If root is empty, default "/" is used.
func NewRootedFS(root string) *RootedFS {
	if root == "" {
		root = "/"
	}
	clean := filepath.Clean(root)
	return &RootedFS{root: clean}
}

// Default returns a RootedFS pointing to the host root "/".
func Default() *RootedFS {
	return NewRootedFS("/")
}

// Root returns the root path.
func (r *RootedFS) Root() string {
	return r.root
}

// Path resolves an absolute Linux path against RootedFS.
func (r *RootedFS) Path(elem ...string) string {
	joined := filepath.Join(elem...)
	if r.root == "/" {
		if !strings.HasPrefix(joined, "/") {
			return "/" + joined
		}
		return joined
	}
	// Trim leading slash before joining with root
	trimmed := strings.TrimPrefix(joined, "/")
	return filepath.Join(r.root, trimmed)
}

// ReadFile reads the given path relative to RootedFS.
func (r *RootedFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(r.Path(name))
}

// ReadDir reads entries from the directory relative to RootedFS.
func (r *RootedFS) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(r.Path(name))
}

// Stat returns FileInfo relative to RootedFS.
func (r *RootedFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(r.Path(name))
}

// Readlink returns symlink target relative to RootedFS.
func (r *RootedFS) Readlink(name string) (string, error) {
	return os.Readlink(r.Path(name))
}

// Open opens a file for reading relative to RootedFS.
func (r *RootedFS) Open(name string) (*os.File, error) {
	return os.Open(r.Path(name))
}

// IsNotExist reports whether the error indicates the file does not exist.
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist)
}

// IsPermission reports whether the error indicates a permission issue.
func IsPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, fs.ErrPermission)
}
