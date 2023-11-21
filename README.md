# TLS AND HTTP2 VIEWER

This project aims to better understand TLS connection and specifications as well as HTTP/2 frames by displaying them in a web page.

## BUILD AND RUN
1. Install Golang on https://go.dev/doc/install
2. Clone the project : `git clone git@github.com:Noooste/tls-http2-viewer.git`
3. Install the dependencies : `go mod download`
4. Build the project by doing `go build -o server .`
5. Run with `./server`

*The server is now up and is listening on port 443*

## USE
Open your navigator and go on the page `https://localhost/get`

An warning should be displayed by your navigator, click on "Visit this website"

## CONFIGURATION
You can also run this project linked to a specific domain. To do so, please modify `config.json` file by changing
`"domain" : "localhost"`
to
`"domain" : "your_domain_here"`

Rebuild the project and run it.
