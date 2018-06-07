// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Extensions to the standard "os" package.
package osext // import "github.com/chennqqi/osext"

// import "github.com/kardianos/osext"
import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

var cx, ce = executableClean()

func executableClean() (string, error) {
	p, err := executable()
	return filepath.Clean(p), err
}

// Executable returns an absolute path that can be used to
// re-invoke the current program.
// It may not be valid after the current program exits.
func Executable() (string, error) {
	return cx, ce
}

// Returns same path as Executable, returns just the folder
// path. Excludes the executable name and any trailing slash.
func ExecutableFolder() (string, error) {
	p, err := Executable()
	if err != nil {
		return "", err
	}

	return filepath.Dir(p), nil
}

func isElfUpxed(appName string) (bool, error) {
	f, err := os.Open(appName)
	if err != nil {
		return false, err
	}

	defer f.Close()
	_elf, err := elf.NewFile(f)

	// Read and decode ELF identifier
	var ident [16]uint8
	f.ReadAt(ident[0:], 0)

	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return false, fmt.Errorf("Bad magic number at %d\n", ident[0:4])
	}

	switch _elf.Class.String() {
	case "ELFCLASS64":
		var hdr elf.Header64
		f.Seek(0, os.SEEK_SET)
		if err := binary.Read(f, _elf.ByteOrder, &hdr); err != nil {
			return false, err
		}
		_elf.Progs[0].Flags.String()
		f.Seek(int64(hdr.Phoff)+int64(hdr.Phentsize)*int64(hdr.Phnum), os.SEEK_SET)

	case "ELFCLASS32":
		var hdr elf.Header32
		f.Seek(0, os.SEEK_SET)
		if err := binary.Read(f, _elf.ByteOrder, &hdr); err != nil {
			return false, err
		}
		f.Seek(int64(hdr.Phoff)+int64(hdr.Phentsize)*int64(hdr.Phnum), os.SEEK_SET)

	default:
		return false, fmt.Errorf("unsupport class", _elf.Class.String())
	}
	var upxMagic [8]byte
	if _, err := f.Read(upxMagic[0:]); err != nil {
		return false, err
	}

	return string(upxMagic[4:]) == "UPX!", nil
}
