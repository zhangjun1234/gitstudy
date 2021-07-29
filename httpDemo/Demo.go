package main

import (
	"io"
	"net/http"
)

func hello(writer http.ResponseWriter, request *http.Request) {
	io.WriteString(writer, "hello world")
}

func main() {
	http.HandleFunc("/hello", hello)
	http.ListenAndServe(":8080", nil)
}
