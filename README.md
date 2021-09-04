# pwned-passwords

[![GoDoc](https://godoc.org/github.com/mattevans/pwned-passwords?status.svg)](https://godoc.org/github.com/mattevans/pwned-passwords)
[![Build Status](https://travis-ci.org/mattevans/pwned-passwords.svg?branch=master)](https://travis-ci.org/mattevans/pwned-passwords)
[![Go Report Card](https://goreportcard.com/badge/github.com/mattevans/pwned-passwords)](https://goreportcard.com/report/github.com/mattevans/pwned-passwords)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/mattevans/pwned-passwords/blob/master/LICENSE)

A light-weight [Go](http://golang.org) client for checking compromised passwords against [HIBP Pwned Passwords](https://haveibeenpwned.com/Passwords).

Installation
-----------------

`go get -u github.com/mattevans/pwned-passwords`

Usage
-----------------

```go
package main

import (
    "fmt"
    "net/http"
    "os"
    "time"

    hibp "github.com/mattevans/pwned-passwords"
)

func main() {
    // Init a client.
    client := hibp.NewClient()

    // Optional: Use a custom http client
    client.SetHTTPClient(&http.Client{
        Timeout: 3 * time.Second,
    })
	
    // Check to see if your given string is compromised.
    pwned, err := client.Compromised("string to check")
    if err != nil {
        os.Exit(1)
    }

    if pwned {
        // Oh dear! 😱 -- You should avoid using that password
        fmt.Print("Found to be compromised")
    }
}
```

Contributing
-----------------
If you've found a bug or would like to contribute, please create an issue here on GitHub, or better yet fork the project and submit a pull request!
