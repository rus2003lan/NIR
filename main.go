package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type VulnItem struct {
	name    string
	regexps []string
}

func InitVulnItem(name string, regexps ...string) VulnItem {
	return VulnItem{name: name, regexps: regexps}
}

func main() {

	var page string
	fmt.Println("Enter the page address:")
	fmt.Scanln(&page)

	resp, err := http.Get(page)
	if err != nil {
		fmt.Println("Invalid page address 1")
		return
	}
	defer resp.Body.Close()

	markup, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Invalid page address 2")
		return
	}

	err = os.WriteFile("page.html", markup, os.FileMode(os.O_WRONLY))
	if err != nil {
		fmt.Println("File wasn't rewritten")
	}

	lines := strings.Split(string(markup), "\n")
	log := ""

	Items := InitVulns()

	for i, line := range lines {
		for _, item := range Items {
			for _, regexp := range item.regexps {
				if PatternCheck(regexp, line) {
					log += strconv.Itoa(i+1) + ":" + line + " - " + item.name + "\n"
				}
			}
		}
	}
	os.WriteFile("log.txt", []byte(log), os.FileMode(os.O_WRONLY))
}

func PatternCheck(pattern string, s string) bool {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		fmt.Printf("Regexp %s is not valid\n", pattern)
	}
	return matched
}

func InitVulns() []VulnItem {
	isLocalhostIP := "<(a|link|area) [^>]*href=\"https?://(localhost|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
	isNumber := "<(a|link|area) [^>]*href=\".+\\?.+=[0-9]+[&\"]"
	isXmlJson := "<input [^>]*accept=\".*(application/xml|\\.xml|application/json|\\.json)"
	isPlCgi := "<input [^>]*accept=\".*(\\.pl|cgi-bin\\/\\*)"
	isImage := "<input [^>]*accept=\".*image\\/\\*"
	isXmlSvg := "<input [^>]*accept=\".*(application/xml|\\.xml|image/svg|\\.svg)"
	isFile := "<input [^>]*type=\"file\"" // фикси с файлом разрешенным
	isAcceptedFile := "<input [^>]*type=\"file\".*accept=\""
	isMedia := "<(img|audio|video) [^>]*src=\".+\\?.+="
	isHidden := "<input [^>]*type=\"hidden\""
	isComment := "<!--.+-->"
	isDevFiles := "<(a|link|area) [^>]*href=\".+\\?.+=(\\.git)" // add files yet
	isAdmin := "<(a|link|area) [^>]*href=\"https?://.+/(admin|administrator)"
	isAsync := "<script [^>]*(defer|async)"
	//isExtension := ""
	//isCategory := ""

	return []VulnItem{InitVulnItem("high (SQLi), low (Command injection)", isNumber), //isCategory),
		InitVulnItem("high (Code injection)", isNumber),
		InitVulnItem("low (SQLi)", isXmlJson),
		InitVulnItem("high (Command injection)", isPlCgi),
		InitVulnItem("low (XXE)", isImage),
		InitVulnItem("high (XXE)", isXmlSvg),
		InitVulnItem("high (SSRF)", isLocalhostIP),
		InitVulnItem("high (File upload)", isFile),
		InitVulnItem("low (File upload)", isAcceptedFile),
		InitVulnItem("high (Path traversal)", isMedia),
		InitVulnItem("high (Information disclosure)", isHidden, isDevFiles, isComment),
		InitVulnItem("high (Access control)", isNumber, isAdmin),
		InitVulnItem("high (Race conditions)", isAsync),
		//InitVulnItem("high (SQLi)", isExtension),
	}
}
