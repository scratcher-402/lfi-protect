package main
import (
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
		)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Files FilesConfig `yaml:"files"`
}
type ProxyConfig struct {
	ListenAddr string `yaml:"listen"`
	ServerAddr string `yaml:"server"`
	MaxReqBodySize int `yaml:"max-req-body-size"`
	CheckURL bool `yaml:"check-url"`
	CheckQuery bool `yaml:"check-query"`
	CheckFilenames bool `yaml:"check-filenames"`
	CheckJSON bool `yaml:"check-json"`
	CheckAllFields bool `yaml:"check-all-fields"`
	CheckFields []string `yaml:"check-fields"`
}
type FilesConfig struct {
	Paths []string `yaml:"paths"`
	Exclude []string `yaml:"exclude"`
}

func main() {
	configFile, err := os.ReadFile("config.yaml")
	if (err != nil) {
		fmt.Println("Config reading error:", err)
		return
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if (err != nil) {
		fmt.Println("Config parsing error:", err)
	}
	fmt.Println("Scr-LFI-Protect")
	trie := NewTrie(&config.Files)
	trie.Setup()
	fmt.Println("Проксируем:", config.Proxy.ServerAddr)
	fmt.Println("Прокси работает на", config.Proxy.ListenAddr)
	proxy, err := NewProxy(&config.Proxy)
	if (err != nil) {
		fmt.Println("Ошибка создания прокси")
		return
	}
	fmt.Println(config)
	http.ListenAndServe(config.Proxy.ListenAddr, proxy)
	}
