# magic

Toolkit for detecting and verifying file type using magic bytes in pure Go.

Support for all file signatures supported by [FreeDesktop](https://gitlab.freedesktop.org/xdg/shared-mime-info/-/raw/master/data/freedesktop.org.xml.in) (and a few more.)

A MIME type, description, and a suggested file extension and icon name are provided for each lookup.

A binary is also included for ease of use.

## Binary Usage

```sh
$ go install github.com/liamg/magic/cmd/latest@latest
$ magic /path/to/file
```

## Module Usage

See the [docs](https://pkg.go.dev/github.com/liamg/magic) for full details.

```go
package main

import (
	"fmt"
	"os"

	"github.com/liamg/magic"
)

func main() {
	ft, err := magic.IdentifyPath(os.Args[1])
	if err != nil {
		fmt.Printf("\x1b[31mError identifying file: %s\x1b[0m\n", err)
		os.Exit(1)
	}

	fmt.Printf("File         %s\n", os.Args[1])
	fmt.Printf("Description  %s\n", ft.Description)
	fmt.Printf("MIME         %s\n", ft.MIME)
	fmt.Printf("Icon         %s\n", ft.Icon)
}
```
