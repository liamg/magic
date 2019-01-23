# magic

[![Travis Build Status](https://travis-ci.org/liamg/magic.svg?branch=master)](https://travis-ci.org/liamg/magic)

Toolkit for detecting and verifying file type using magic bytes in pure Go

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
        }else{
            panic(err)
        }
    }

    fmt.Printf("File extension:        %s\n", fileType.Extension)
    fmt.Printf("File MIME type:        %s\n", fileType.MIME)
    fmt.Printf("File type description: %s\n", fileType.Description)
}
```