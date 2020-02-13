package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
)


func readToken() []byte {
	file, err := os.Open("/var/run/secrets/tokens/vault-token")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	return bytes
}

func requestWithToken(w http.ResponseWriter, r *http.Request) {
	token := readToken()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://token-server:8090", nil)
	req.Header.Set("X-Auth-Token", string(token))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		w.Write([]byte("403 : StatusForbidden"))
		return
	} else if resp.StatusCode == http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		w.Write(body)
	}

}

func main()  {
	log.Println("Starting token-client")

	http.HandleFunc("/", requestWithToken)

	http.ListenAndServe(":8090", nil)
}