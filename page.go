package main

import (
	"fmt"
	"io"
	"os"
)

type VulnItem struct {
	name    string
	regexps []string
}

type Page struct {
	url string
	body io.ReadCloser
	markup []byte
	log  string
}

func (p *Page) WriteMarkup() {
	err := os.WriteFile("page.html", p.markup, os.FileMode(os.O_WRONLY))
	if err != nil {
		fmt.Println("File wasn't rewritten")
	}
}
