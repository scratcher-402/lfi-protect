package main
import (
	"fmt"
	"net/http"
		)

func main() {
	fmt.Println("Hello Goida")
	proxy, err := NewProxy("http://localhost:8999/")
	if (err != nil) {
		fmt.Println("Ошибка созлания прокси")
		return
	}
	http.ListenAndServe(":8000", proxy)
	}
