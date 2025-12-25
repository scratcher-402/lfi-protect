package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"net"
	"fmt"
	"regexp"
	)

type Proxy struct {
	baseURL *url.URL
	proxy *httputil.ReverseProxy
}


func NewProxy(baseURL string) (*Proxy, error) {
	base, err := url.Parse(baseURL)
	if (err != nil) {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(base)

	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		ip, _, _ := net.SplitHostPort(req.RemoteAddr)
		originalDirector(req)
		req.Header.Set("X-Real-IP", string(ip))
		fmt.Println("[ ... ]", req.Method, req.URL.Path)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Printf("[  !  ] Proxy error: %v\n", err)
	}

	return &Proxy{proxy: proxy, baseURL: base}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lfi_pattern := regexp.MustCompile(`.*\.\./.*`)
	if blocked := checkURL(r, lfi_pattern); blocked != nil {
		w.Header().Set("Content-Type", "text/html; charset: utf-8")
		w.Header().Set("X-Blocked", "true")
		w.WriteHeader(http.StatusForbidden)
		html := `<!DOCTYPE html>
				 <html lang="en">
				 <head><title>Request blocked due to security reasons</title></head>
				 <body><h1>Request blocked due to security reasons</h1>Scr-LFI-Protect</body>
				 </html>`
		w.Write([]byte(html))
		fmt.Println("[ -X  ] Request blocked")
		return
		}
	p.proxy.ServeHTTP(w, r)
	fmt.Println("[ --> ] Request sent")
}

func checkURL(req *http.Request, pattern *regexp.Regexp) error {
	for _, values := range req.URL.Query() {
		for _, value := range values {
			if pattern.MatchString(value) {
				return fmt.Errorf("Pattern in query detected")
			}
		}
	}
	return nil
}

