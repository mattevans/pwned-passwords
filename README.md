# pwned-passwords

[![GoDoc](https://godoc.org/github.com/mattevans/pwned-passwords?status.svg)](https://godoc.org/github.com/mattevans/pwned-passwords)
[![Build Status](https://travis-ci.org/mattevans/pwned-passwords.svg?branch=master)](https://travis-ci.org/mattevans/pwned-passwords)
[![Go Report Card](https://goreportcard.com/badge/github.com/mattevans/pwned-passwords)](https://goreportcard.com/report/github.com/mattevans/pwned-passwords)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/mattevans/pwned-passwords/blob/master/LICENSE)

A simple [Go](http://golang.org) client library for checking compromised passwords against [HIBP Pwned Passwords](https://haveibeenpwned.com/Passwords).

Upon request, results will be cached (in-memory) for a configurable window, keyed by hash.

Installation
-----------------

`go get -u github.com/mattevans/pwned-passwords`

Usage
-----------------

```go
package main

import (
    "fmt"
    "os"
    "time"

    hibp "github.com/mattevans/pwned-passwords"
)

const (
    storeExpiry = 1 * time.Hour
)

func main() {
    // Init a client.
    client := hibp.NewClient(storeExpiry)

    // Check to see if your given string is compromised.
    pwned, err := client.Pwned.Compromised("string to check")
    if err != nil {
        os.Exit(1)
    }

    if pwned {
        // Oh dear! 😱
        // You should avoid using that password
    }
}
```

**Managing the inmemory store**

```go
// Delete will remove an item from the store by hash.
client.Store.Delete(HASHED_VALUE)
```

```go
// DeleteExpired will remove all expired items from the store.
client.Store.DeleteExpired()
```

```go
// PurgeAll will flush the store.
client.Store.PurgeAll()
```

Contributing
-----------------
If you've found a bug or would like to contribute, please create an issue here on GitHub, or better yet fork the project and submit a pull request!
