import requests
from bs4 import BeautifulSoup
import  re
from urllib.parse import urlparse


URL = "https://github.com/RusGadzhiev"
HOST = urlparse(URL)[0] + '://' + urlparse(URL)[1]
HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

input_regexps = {
    'IsXmlJson': "<input [^>]*accept=\".*(application/xml|\\.xml|application/json|\\.json)",
    'IsPlCgi': "<input [^>]*accept=\".*(\\.pl|cgi-bin\\/\\*)",
    'IsImage': "<input [^>]*accept=\".*image\\/\\*",
    'IsXmlSvg': "<input [^>]*accept=\".*(application/xml|\\.xml|image/svg|\\.svg)",
    'IsFile': "<input [^>]*type=\"file\"",
    'IsAcceptedFile': "<input [^>]*type=\"file\".*accept=\""
}

script_regexps = {
    'XMLHttpRequestGET': ".open(\"GET\" [^>]*)",
    'XMLHttpRequestPOST': ".open(\"POST\" [^>]*)",
    '$.get': "$\\.get([^>]*)",
    '$.post': "$\\.get([^>]*)",
    '$.getJSON': "$\\.getJSON([^>]*)",
    '$.ajax': "$\\.ajax([^>]*)",
    'fetch': " fetch([^>]*)",
    'axios.get': "axios\\.get([^>]*)",
    'superagent.get': "superagent\\.get([^>]*)",
    'superagent.post': "superagent\\.post([^>]*)",
    'axios.post': "axios\\.post([^>]*)",
}


def get_scripts(soup: BeautifulSoup):
    scripts = soup.find_all("script")
    str_scripts = [str(script) for script in scripts]
    file = open("scripts.js", "w")
    for s in str_scripts:
        file.write(s)
    file.write('\n\n\n')

    src_list = []
    for script in scripts:
        src = script.get("src")
        if src is not None:
            src_list.append(src)

    for src in src_list:
        try:
            r = requests.get(HOST + src, headers=HEADERS)
            file.write(r.text)
            file.write('\n\n\n')
            str_scripts.append(r.text)
        except:
            pass
    file.close()
    return str_scripts


def html_check(soup: BeautifulSoup):
    file = open("log.txt", "w")
    forms = soup.find_all("form")
    for form in forms:
        method = form.get('method')
        uri = form.get('action')
        if not (urlparse(uri).netloc == urlparse(URL).netloc or urlparse(uri).netloc == ''):
            continue
        if uri == '':
            uri = '/'
        keys = {}
        inputs = form.find_all('input')
        for input in inputs:
            name = input.get('name')
            if not name:
                continue
            keys[name] = []
            for comment, r in input_regexps.items():
                if re.match(r, str(input)):
                    keys[name].append(comment)
        file.write(method + ' ' + uri + ' ' + str(keys) + '\n')
    file.close()

def scripts_check(scripts):
    file = open("log2.txt", "w")
    for script in scripts:
        for r in script_regexps.values():
            if re.match(r, script):
                file.write(script)
                file.write('\n')
    file.close()

def main():
    r = requests.get(URL, headers=HEADERS)
    file = open("page.html", "w")
    file.write(r.text)
    file.close()

    soup = BeautifulSoup(r.content, "html.parser")
    html_check(soup)
    scripts_check(get_scripts(soup))


main()
