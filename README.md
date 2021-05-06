# [Tiny Encryption Algorithm](https://github.com/x2ox/tea)


[![JetBrains Open Source Licenses](https://img.shields.io/badge/-JetBrains%20Open%20Source%20License-000?style=flat-square&logo=JetBrains&logoColor=fff&labelColor=000)](https://www.jetbrains.com/?from=blackdatura)
[![GoDoc](https://pkg.go.dev/badge/go.x2ox.com/tea.svg)](https://pkg.go.dev/go.x2ox.com/tea)
[![Sourcegraph](https://sourcegraph.com/github.com/x2ox/tea/-/badge.svg)](https://sourcegraph.com/github.com/x2ox/tea?badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/x2ox/tea)](https://goreportcard.com/report/github.com/x2ox/tea)
[![Release](https://img.shields.io/github/v/release/x2ox/tea.svg)](https://github.com/x2ox/tea/releases)
[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

## Example
```go
package main

import (
	"bytes"
	"fmt"
	
	"go.x2ox.com/tea"
)

func main() {
	out := make([]byte, 8)

	c, err := tea.NewTEA([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	if err != nil {
		fmt.Println(err)
		return
	}

	c.Encrypt(out, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	if bytes.Compare(out, []byte{0xDE, 0xB1, 0xC0, 0xA2, 0x7E, 0x74, 0x5D, 0xB3}) != 0 {
		fmt.Println(err)
	}
}

```
