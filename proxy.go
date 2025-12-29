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
	"encoding/json"
	"time"
	)

type Proxy struct {
	baseURL *url.URL
	proxy *httputil.ReverseProxy
	LFIPattern *regexp.Regexp
	config *ProxyConfig
	checkFields map[string]bool
}


func NewProxy(config *ProxyConfig, trie *Trie) (*Proxy, error) {
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
		if strings.Contains(err.Error(), "LFI") || strings.Contains(err.Error(), "File leak") {
			w.Header().Set("Content-Type", "text/html; charset: utf-8")
			w.Header().Set("X-Blocked", "true")
			w.WriteHeader(http.StatusForbidden)
			w.Write(RenderBlockMessage())
		} else {
			w.Header().Set("Content-Type", "text/html; charset: utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RenderErrorMessage())
		}
		fmt.Printf("[  !  ] Proxy error: %v\n", err)
	}

	LFIPattern := regexp.MustCompile(`.*\.\./.*`)

	checkFields := map[string]bool{}
	for _, fieldName := range config.CheckFields {
		checkFields[fieldName] = true
	}

	originalModifyResponse := proxy.ModifyResponse
	proxy.ModifyResponse = func (resp *http.Response) error {
		if originalModifyResponse != nil {
			err := originalModifyResponse(resp)
			if err != nil {
				return err
			}
		}
		if config.CheckFileLeaks {
			fmt.Println("Analyzing response")
			var bodyBuffer bytes.Buffer	
			bodyReader := io.TeeReader(resp.Body, &bodyBuffer)
			body, err := io.ReadAll(bodyReader)
			if err != nil {
				resp.Body = io.NopCloser(&bodyBuffer)
				return err
			}
			fmt.Println("Body read")
			err = trie.AnalyzeBytes(&body)
			if err != nil {
				return err
			}
			fmt.Println("Body analyzed")
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		return nil
	}

	return &Proxy{proxy: proxy, config: config, LFIPattern: LFIPattern, checkFields: checkFields}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := p.checkURL(r)
	if err != nil {
		if strings.Contains(err.Error(), "LFI") {
			p.sendBlockMessage(w, r)
			return
		} else {
			fmt.Println(err)
			p.sendErrorMessage(w, r)
			return
		}
	}
	err = p.checkRequestBody(r)
	if err != nil {
		if strings.Contains(err.Error(), "LFI") {
			p.sendBlockMessage(w, r)
			return
		} else {
			fmt.Println(err)
			p.sendErrorMessage(w, r)
			return
		}
	}
	p.proxy.ServeHTTP(w, r)
	fmt.Println("[ --> ] Request sent")
}

func (p *Proxy) sendBlockMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset: utf-8")
	w.Header().Set("X-Blocked", "true")
	w.WriteHeader(http.StatusForbidden)
	w.Write(RenderBlockMessage())
	fmt.Println("[ -X  ] Request blocked")
}
func RenderBlockMessage() []byte {
	timeString := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
				 			  <html lang="en">
				 			  <head>
				 			  	<title>Access Denied</title>
							  </head>
							  <body>
				 			   	<h1>Access Denied</h1>
				 				<p>Your request has been blocked by our security system.</p>
				 				<p>If you believe this is an error, please contact support.</p>
				 				Time: %s<br>
				 				Scr-LFI-Protect
				 			  </body>
				 			  </html>`, timeString))
}
func (p *Proxy) sendErrorMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset: utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(RenderErrorMessage())
	fmt.Println("[  !  ] Request processing error")
}
func RenderErrorMessage() []byte {
	timeString := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
				 			   <html lang="en">
				 			   <head>
				 			 	 <title>Internal Server Error</title>
				 			   </head>
				 			   <body>
				 			 	 <h1>Internal Server Error</h1>
				 			 	 <p>An unexpected error occured while processing your request.</p>
				 			 	 <p>Please try again later or contact support if the problem persists.</p>
				 			 	 Time: %s<br>
				 			 	 Scr-LFI-Protect
				 		       </body>
				 			   </html>`, timeString))
}

func (p *Proxy) checkRequestBody(r *http.Request) error {
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
	if !p.config.CheckQuery && !p.config.CheckFilenames {
		return nil
	}

	var bodyBuffer bytes.Buffer
	bodyReader := io.TeeReader(r.Body, &bodyBuffer)
	reqParse := &http.Request{
		Method: r.Method,
		Header: r.Header,
		Body: io.NopCloser(bodyReader),
	}

	reader, err := reqParse.MultipartReader()
	if err != nil {
		return err
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		field := part.FormName()
		fileName := part.FileName()

		if fileName != "" {
			if p.LFIPattern.MatchString(fileName) {
				return fmt.Errorf("LFI pattern in filename detected")
			}
		} else {
			if p.fieldCheckNeeded(field) {
				value, err := io.ReadAll(part)
				if err != nil {
					return err
				}
				if p.LFIPattern.Match(value) {
					return fmt.Errorf("LFI pattern in form field detected")
				}
			}
		}
	}

	r.Body = io.NopCloser(&bodyBuffer)
	return nil
}

func (p *Proxy) checkRequestJSON(r *http.Request) error {
	if (!p.config.CheckJSON) {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(p.config.MaxReqBodySize)))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var jsonData interface{}
	err = decoder.Decode(&jsonData)
	if err != nil {
		return err
	}
	err = p.scanJSON(jsonData)
	return err
}

func (p *Proxy) scanJSON(jsonData interface{}) error {
	var err error
	switch jsonData.(type) {
		case map[string]interface{}:
			for key, value := range jsonData.(map[string]interface{}) {
				switch value.(type) {
					case string:
						if p.fieldCheckNeeded(key) {
							if p.LFIPattern.MatchString(value.(string)) {
								return fmt.Errorf("LFI pattern detected in JSON field")
							}
						}
					default:
						err = p.scanJSON(value)
						if err != nil {
							return err
						}
				}
			}
		case []interface{}:
			for _, value := range jsonData.([]interface{}) {
				err = p.scanJSON(value)
				if err != nil {
					return err
				}
			}
		case string:
			if p.fieldCheckNeeded("*") {
				if p.LFIPattern.MatchString(jsonData.(string)) {
					return fmt.Errorf("LFI pattern in JSON field detected")
				}
			}
		case json.Number:
			break
		case bool, nil:
			break
	}
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
