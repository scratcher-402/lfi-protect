package main
import (
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
		)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
}
type ProxyConfig struct {
	ListenAddr string `yaml:"listen"`
	ServerAddr string `yaml:"server"`
}

func main() {
	configFile, err := os.ReadFile("config.yaml")
	if (err != nil) {
		fmt.Println("Ошибка чтения конфига", err)
		return
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if (err != nil) {
		fmt.Println("Ошибка парсинга", err)
	}
	fmt.Println("Scr-LFI-Protect")
	fmt.Println("Проксируем:", config.Proxy.ServerAddr)
	fmt.Println("Прокси работает на", config.Proxy.ListenAddr)
	proxy, err := NewProxy(config.Proxy.ServerAddr)
	if (err != nil) {
		fmt.Println("Ошибка создания прокси")
		return
	}
	http.ListenAndServe(config.Proxy.ListenAddr, proxy)
	}
