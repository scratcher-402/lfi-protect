package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"net"
	"fmt"
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
		fmt.Println("Обнаружен IP:", ip)
		originalDirector(req)
		req.Header.Set("X-Real-IP", string(ip))
		fmt.Println("Проксируется запрос", req.Method, req.URL.Path)
	}

	return &Proxy{proxy: proxy, baseURL: base}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}
