// hashpass reads a password from stdin and prints an argon2id PHC string
// suitable for the `pass` field of a go-socks5 user entry.
//
// Passwords are read only from stdin; passing them on the command line would
// expose the cleartext via process listings (ps, /proc).
//
//	$ echo -n "hunter2" | hashpass
//	$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gumeniukcom/go-socks5/internal/proxy"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "hashpass: passwords must be supplied on stdin, not as arguments")
		os.Exit(2)
	}
	pw, err := readPassword(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashpass:", err)
		os.Exit(1)
	}
	encoded, err := proxy.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashpass:", err)
		os.Exit(1)
	}
	fmt.Println(encoded)
}

func readPassword(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	// Trim a single trailing newline; preserve other whitespace.
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
		if n2 := len(line); n2 > 0 && line[n2-1] == '\r' {
			line = line[:n2-1]
		}
	}
	if len(line) == 0 {
		return nil, errors.New("empty password")
	}
	return line, nil
}
