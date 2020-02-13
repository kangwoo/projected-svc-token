package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)


const audience = "vault"

func readServiceAccountToken() []byte {
	file, err := os.Open("/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	byes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	return byes
}

func validateToken(boundToken, serviceAccountTOken string) bool {

	reviewPayload := []byte(`{"kind": "TokenReview","apiVersion": "authentication.k8s.io/v1","spec": {"token": "` + serviceAccountTOken + `"}}`)
	body := bytes.NewBuffer(reviewPayload)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://kubernetes.default:443/apis/authentication.k8s.io/v1/tokenreviews", body)

	req.Header.Add("Authorization", "Bearer " +boundToken)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failure : %s", err)
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		log.Printf("Error unmarshaling response %s", err)
	}

	if respData["status"].(map[string]interface{})["authenticated"] == true {

		if validateAudiences(respData["status"].(map[string]interface{})["audiences"].([]interface{})) {
			return true
		} else {
			log.Printf("Audience validation failed.")
		}

	} else {
		log.Printf("Authenticated failed.")
	}

	return false
}

func validateAudiences(audiences []interface{}) bool {
	for _, v := range audiences {
		if v == audience {
			return true
		}
		continue
	}

	return false
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	svcAcctToken := readServiceAccountToken()
	if validateToken(string(svcAcctToken), r.Header.Get("X-Auth-Token")) != true {
		w.WriteHeader(403)
		return
	}

	w.Write([]byte("Hello, This is token-server"))

}

func main()  {
	log.Println("Starting token-server")

	http.HandleFunc("/", requestHandler)

	http.ListenAndServe(":8090", nil)

}