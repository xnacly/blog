---
title: "Stop Using python -m http for developing static html pages"
date: 2025-11-09
draft: true
tags:
- python
- go
---

<!-- TODO: Explain: --> 

1. not paralell, using it with more than one consumer results in timeouts
2. 

Fix:

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

type NoCacheHandler struct {
	handler http.Handler
}

func (h NoCacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	clientIP := r.RemoteAddr
	log.Printf("%s - - [%s] %s %s %s",
		clientIP,
		r.Header.Get("Date"),
		r.Method,
		r.RequestURI,
		r.Proto,
	)

	h.handler.ServeHTTP(w, r)
}

func main() {
	host := "0.0.0.0"
	port := 8080
	addr := fmt.Sprintf("%s:%d", host, port)

	fs := http.FileServer(http.Dir("."))

	handler := NoCacheHandler{handler: fs}

	fmt.Printf("Serving on http://%s\n", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}
```
