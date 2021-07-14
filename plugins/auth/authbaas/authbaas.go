package authbaas

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/fhmq/hmq/logger"
	"go.uber.org/zap"
)

var (
	log = logger.Get().Named("authhttp")
)

type authBaas struct {
	authURL *url.URL
	client  *http.Client
	auth    string
}

func Init() *authBaas {
	c := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost:     100,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: time.Second * 100,
	}

	u, _ := url.Parse("http://localhost:8080/login/auth")
	a := &authBaas{
		authURL: u,
		client:  c,
	}
	a.getEnv()

	return a
}

func (a *authBaas) getEnv() {
	if h := os.Getenv("AUTH_HOST"); len(h) > 0 {
		a.authURL.Host = h
	}

	if p := os.Getenv("AUTH_PATH"); len(p) > 0 {
		a.authURL.Path = p
	}

	if ba := os.Getenv("Authorization"); len(ba) > 0 {
		a.auth = ba
	}
}

func (a *authBaas) CheckConnect(clientID, username, password string) bool {
	return true
}

func (a *authBaas) CheckACL(action, clientID, username, ip, topic string) bool {
	if action == "2" {
		return true
	}

	a.authURL.Scheme = "https"
	req, err := http.NewRequest("GET", a.authURL.String(), nil)
	if err != nil {
		log.Error("new request super: ", zap.Error(err))
		return false
	}
	req.Header.Add("Authorization", a.auth)
	q := req.URL.Query()
	q.Add("_sub", username)
	q.Add("_path", topic)
	q.Add("kld-from", username)
	req.URL.RawQuery = q.Encode()

	resp, err := a.client.Do(req)
	if err != nil {
		log.Error("request super: ", zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		zap.Error(err)
		return false
	}

	if v, ok := data["output"]; ok {
		return v.(bool)
	}
	return false
}
