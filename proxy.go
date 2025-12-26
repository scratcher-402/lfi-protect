package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"net"
	"fmt"
	"regexp"
	"strings"
	"bytes"
	"io"
	)

type Proxy struct {
	baseURL *url.URL
	proxy *httputil.ReverseProxy
	LFIPattern *regexp.Regexp
	config *ProxyConfig
	checkFields map[string]bool
}


func NewProxy(config *ProxyConfig) (*Proxy, error) {
	base, err := url.Parse(config.ServerAddr)
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

	LFIPattern := regexp.MustCompile(`.*\.\./.*`)

	checkFields := map[string]bool{}
	for _, fieldName := range config.CheckFields {
		checkFields[fieldName] = true
	}

	return &Proxy{proxy: proxy, config: config, LFIPattern: LFIPattern, checkFields: checkFields}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	URLBlocked := p.checkURL(r)
	bodyBlocked := p.checkRequestBody(r)
	if URLBlocked != nil || bodyBlocked != nil {
		p.sendBlockMessage(w, r)
		return
		}
	p.proxy.ServeHTTP(w, r)
	fmt.Println("[ --> ] Request sent")
}

func (p *Proxy) sendBlockMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset: utf-8")
	w.Header().Set("X-Blocked", "true")
	w.WriteHeader(http.StatusForbidden)
	html := `<!DOCTYPE html>
			 <html lang="en">
			 <head>
			 	<title>Request blocked due to security reasons</title>
			 </head>
			 <body>
			 	<h1>Request blocked due to security policy</h1>
			 	Scr-LFI-Protect
			 </body>
			 </html>`
	w.Write([]byte(html))
	fmt.Println("[ -X  ] Request blocked")
	return
}

func (p *Proxy) checkRequestBody(r *http.Request) error {
	fmt.Println(r)
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return p.checkRequestForm(r)
	}
	if strings.Contains(contentType, "multipart/form-data") {
		return p.checkRequestMultipartForm(r)
	}
	if strings.Contains(contentType, "application/json") {
		return p.checkRequestJSON(r)
	}
	return nil
	}

func (p *Proxy) checkRequestForm(r *http.Request) error {
	if !p.config.CheckQuery {
		return nil
	}
	
	var bodyBuffer bytes.Buffer
	bodyReader := io.TeeReader(r.Body, &bodyBuffer)
	reqParse := &http.Request{
		Method: r.Method,
		Header: r.Header,
		Body: io.NopCloser(bodyReader),
	}

	err := reqParse.ParseForm()
	if (err != nil) {
		return err
	}
	for field, values := range reqParse.PostForm {
		for _, value := range values {
			if p.fieldCheckNeeded(field) {
				if p.LFIPattern.MatchString(value) {
					return fmt.Errorf("LFI Pattern in form field detected")
				}
			}
		}
	}

	r.Body = io.NopCloser(&bodyBuffer)
	return nil
}

func (p *Proxy) checkRequestMultipartForm(r *http.Request) error {
	return nil
}

func (p *Proxy) checkRequestJSON(r *http.Request) error {
	return nil
}

func (p *Proxy) checkURL(req *http.Request) error {
	if p.config.CheckURL {
		if p.LFIPattern.MatchString(req.URL.String()) {
			return fmt.Errorf("LFI Pattern in URL detected")
		}
	}
	if !p.config.CheckQuery {
		return nil
	}
	for key, values := range req.URL.Query() {
		for _, value := range values {
			if p.fieldCheckNeeded(key) {
				if p.LFIPattern.MatchString(value) {
					return fmt.Errorf("LFI Pattern in query detected")
				}
			}
		}
	}
	return nil
}

func (p *Proxy) fieldCheckNeeded(fieldName string) bool {
	if p.config.CheckAllFields {
		return true
	}
	value, exists := p.checkFields[fieldName]
	if !exists {
		return false
	}
	return value
}
