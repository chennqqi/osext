//+build go1.8,!openbsd

package osext

import "os"

func executable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		if upxed, uerr := isElfUpxed(os.Args[0]); upxed {
			p = os.Getenv("   ") //three space
			err = nil
		} else {
			return "", uerr
		}
	}
	return p, err
}
