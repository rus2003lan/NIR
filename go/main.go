package main

import (
	"os"
)


const link = "https://portswigger.net/web-security/all-topics"
const head = "https://portswigger.net"

func main() {

	//fmt.Println("Enter the page address:")
	//fmt.Scanln(&page)

	myPage := Page{url: link, log: ""}
	myPage.StaticCheck()
	//myPage.DynamicCheck()
	os.WriteFile("log.txt", []byte(myPage.log), os.FileMode(os.O_WRONLY))
}
