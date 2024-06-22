package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	IsLocalhostIP  = "<(a|link|area) [^>]*href=\"https?://(localhost|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
	IsNumber       = "<(a|link|area) [^>]*href=\".+\\?.+=[0-9]+[&\"]"
	IsXmlJson      = "<input [^>]*accept=\".*(application/xml|\\.xml|application/json|\\.json)"
	IsPlCgi        = "<input [^>]*accept=\".*(\\.pl|cgi-bin\\/\\*)"
	IsImage        = "<input [^>]*accept=\".*image\\/\\*"
	IsXmlSvg       = "<input [^>]*accept=\".*(application/xml|\\.xml|image/svg|\\.svg)"
	IsFile         = "<input [^>]*type=\"file\""
	IsAcceptedFile = "<input [^>]*type=\"file\".*accept=\""
	IsMedia        = "<(img|audio|video) [^>]*src=\".+\\?.+="
	IsHidden       = "<input [^>]*type=\"hidden\""
	IsComment      = "<!--.+-->"
	IsDevFiles     = "<(a|link|area) [^>]*href=\".+\\?.+=(\\.git)"
	IsAdmin        = "<(a|link|area) [^>]*href=\"https?://.+/(admin|adminIstrator)"
	IsScrypt       = `<script([\s\S]*?)</script>`
	IsSRC          = `<script.*src="(.*?[^\n])"`
)

var (
	Static = []string{("Command injection", IsNumber, IsPlCgi),
		("Code injection", IsNumber),
		("SQLi", IsXmlJson, IsNumber),
		("XXE", IsImage, IsXmlSvg),
		("SSRF", IsLocalhostIP),
		("File upload", IsFile, IsAcceptedFile),
		("Path traversal", IsMedia),
		("Information dIsclosure", IsHidden, IsDevFiles, IsComment),
		("Access control", IsNumber, IsAdmin),
	}
)

func (p *Page) StaticCheck() {

	resp, err := http.Get(p.url)
	if err != nil {
		fmt.Println("Invalid page address 1")
		return
	}

	markup, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Invalid page address 2")
		return
	}
	p.body = resp.Body
	p.markup = markup
	p.WriteMarkup()

	p.log += "Static Check:\n"

	//p.HTMLCheck()
	p.JSCheck()
	resp.Body.Close()
}

func PatternCheck(pattern string, s string) bool {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false
	}
	return matched
}

func (p *Page) HTMLCheck() {
	lines := strings.Split(string(p.markup), "\n")

	for i, line := range lines {
		for _, item := range StaticVulns {
			for _, regexp := range item.regexps {
				if PatternCheck(regexp, line) {
					p.log += strconv.Itoa(i+1) + ":" + line + " - " + item.name + "\n"
				} else {
					p.log += fmt.Sprintf("Regexp: %s , is not valid\n", regexp)
				}
			}
		}
	}
}

func (p *Page) JSCheck() {
	scripts := p.GetScripts()
	// сделай что-то со скриптами
	_ = scripts

}

func (p *Page) GetScripts() []string {
	scripts := Substr(string(p.markup), IsScrypt)
	for i, script := range scripts {
		links := Substr(script, IsSRC)
		if links != nil {
			scripts[i] = string(DownloadLink(head + CleanLink(links[0])))
		}
	}
	return scripts
}

func DownloadLink(link string) []byte {
	resp, err := http.Get(link)
	if err != nil {
		fmt.Println("Invalid page address DownloadLink: " + link)
		return nil
	}
	defer resp.Body.Close()

	script, _ := io.ReadAll(resp.Body)
	return script
}

func Substr(s string, reg string) []string {
	var r = regexp.MustCompile(reg)
	matched, err := regexp.MatchString(reg, s)
	if err != nil {
		fmt.Println(err)
		return nil
	} else if !matched {
		return nil
	}
	all := r.FindAllString(s, -1)
	return all
}

func CleanLink(link string) string {
	_, after, found := strings.Cut(link, `src="`)
	if !found {
		fmt.Println("error CleanLink")
		return ""
	}
	l, _, found := strings.Cut(after, `"`)
	if !found {
		fmt.Println("error CleanLink")
		return ""
	}
	return l
}
