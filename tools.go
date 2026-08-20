//go:build tools

// This file exists only to keep the mage build tool in go.mod/go.sum. The
// magefile (magefile.go) is compiled by mage under the `mage` build tag, which
// `go mod tidy` does not see, so without this pin tidy would drop the
// dependency. It is never compiled into any real binary.
package tools

import (
	_ "github.com/magefile/mage/mg"
	_ "github.com/magefile/mage/sh"
)
