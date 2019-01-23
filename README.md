# magic

[![Travis Build Status](https://travis-ci.org/liamg/magic.svg?branch=master)](https://travis-ci.org/liamg/magic)

Toolkit for detecting and verifying file type using magic bytes in pure Go

Support for all file signatures listed [here](https://en.wikipedia.org/wiki/List_of_file_signatures).

You only need to provide the first few hundred bytes of a given file to detect the file type, unless you want to detect `.iso` images, which require examination of the first 32774 bytes.

A description and a suggested file extension are provided where relevant, and MIME types will be added in future.

## Example Usage

```go
package main

import "github.com/liamg/magic"

func main() {

    data := []byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00}

    fileType, err := magic.Lookup(data)
    if err != nil {
        if err == magic.ErrUnknown {
            fmt.Println("File type is unknown")
            os.Exit(1)
        }else{
            panic(err)
        }
    }

    fmt.Printf("File extension:        %s\n", fileType.Extension)
    fmt.Printf("File type description: %s\n", fileType.Description)
}
```