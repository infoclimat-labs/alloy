//go:build !unix

package main

import "os"

// File locking is only implemented on Unix; elsewhere concurrent runs must
// be avoided.
func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
