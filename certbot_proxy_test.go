package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	//os.Exit(m.Run())
	m.Run()
}

// Helpers
func executeTestRequest(r *http.Request, handler http.HandlerFunc) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(handler)
	h.ServeHTTP(rr, r)
	return rr
}

func randomSting(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz-0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func (token *CertToken) setRandomToken() {
	token.Domain = randomSting(20) + "." + randomSting(4)
	token.Token = randomSting(40)
	token.Validation = randomSting(40)
}

func (token *CertToken) json() []byte {
	td, err := json.Marshal(token)
	if err != nil {
		log.Fatal(err)
	}
	return td
}

func genRandomToken() CertToken {
	t := CertToken{}
	t.setRandomToken()
	return t
}

func (token *CertToken) executeRequest(t *testing.T, method string) *httptest.ResponseRecorder {
	req := token.newTestRequest(t, method)
	return executeTestRequest(req, acmeTokenHandler)
}

func (token *CertToken) newTestChallangeRequest(t *testing.T, method string) *http.Request {
	return newTestRequest(t, method, fmt.Sprintf("http://%s%s%s", token.Domain, acmeChallangePath, token.Token), nil)
}

func (token *CertToken) getValidation(t *testing.T) (*httptest.ResponseRecorder, string) {
	req := token.newTestChallangeRequest(t, http.MethodGet)
	//req := newTestRequest(t, http.MethodGet, fmt.Sprintf("http://%s%s%s", token.Domain, acmeChallangePath, token.Token), nil)
	rr := executeTestRequest(req, acmeChallangeHandler)
	s := ""
	if rr.Code == http.StatusOK {
		body, err := ioutil.ReadAll(rr.Body)
		if err != nil {
			t.Fatal(err)
		}
		s = string(body)
	}
	return rr, s
}

func executeToken(t *testing.T, method string, token CertToken) *httptest.ResponseRecorder {
	td, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	return executeTokenJson(t, method, td)
}

func newTestRequest(t *testing.T, method string, path string, data []byte) *http.Request {
	req, err := http.NewRequest(method, path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func (token *CertToken) newTestRequest(t *testing.T, method string) *http.Request {
	req := newTestRequest(t, method, tokenPostPath, token.json())
	req.Header.Add("Content-Type", "application/json")
	return req
}

func executeTokenJson(t *testing.T, method string, data []byte) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, tokenPostPath, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Forwarded-For", "192.168.1.1")
	return executeTestRequest(req, acmeTokenHandler)
}

// Tests
func TestAcmeTokenHandlerNilBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, tokenPostPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := executeTestRequest(req, acmeTokenHandler)
	assert.Equal(t, rr.Code, http.StatusBadRequest)
}

func TestAcmeTokenHandlerNotJson(t *testing.T) {
	rr := executeTokenJson(t, http.MethodPost, []byte("Dette er ikke JSON"))
	assert.Equal(t, rr.Code, http.StatusBadRequest)
}

func TestAcmeTokenHandlerBadMethod(t *testing.T) {
	token := genRandomToken()
	rr := executeToken(t, http.MethodGet, token)
	assert.Equal(t, rr.Code, http.StatusMethodNotAllowed)
}

func TestAcmeTokenHandlerEmptyToken(t *testing.T) {
	token := CertToken{}
	rr := executeToken(t, http.MethodPost, token)
	assert.Equal(t, rr.Code, http.StatusBadRequest, "Empty token test")
}

func TestAcmeTokenHandlerSetAndDelete(t *testing.T) {
	token := genRandomToken()
	rr := executeToken(t, http.MethodPost, token)
	assert.Equal(t, rr.Code, http.StatusOK, "Test valid token post")

	// Test valid token from acme view
	rr, v := token.getValidation(t)
	assert.Equal(t, rr.Code, http.StatusOK, "Test valid token return code from acme view")
	assert.Equal(t, v, token.Validation, "Test valid token from acme view")

	// Test invalid method from acme view
	req := token.newTestChallangeRequest(t, http.MethodPost)
	rr = executeTestRequest(req, acmeChallangeHandler)
	assert.Equal(t, rr.Code, http.StatusMethodNotAllowed, "Test invalid method from acme view")

	// Test invalid token path from acme view
	token.Token = "invalid_token"
	rr, v = token.getValidation(t)
	assert.Equal(t, rr.Code, http.StatusNotFound, "Test invalid token path from acme view")

	// Delete token
	req = token.newTestRequest(t, http.MethodDelete)
	req.RemoteAddr = "127.0.0.1"
	rr = executeTestRequest(req, acmeTokenHandler)
	assert.Equal(t, rr.Code, http.StatusOK, "Test valid token delete (with remote address)")
}

func TestAcmeChallangeHandlerInvalidUrl(t *testing.T) {
	// Test invalid URL
	req, err := http.NewRequest(http.MethodGet, acmeChallangePath+"test.dk", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := executeTestRequest(req, acmeChallangeHandler)
	assert.Equal(t, rr.Code, http.StatusNotFound)
}

func TestTokenLimit(t *testing.T) {
	localTokens := make(map[string]byte)
	for len(localTokens) < MAX_TOKENS+1 {
		token := genRandomToken()
		localTokens[token.Domain] = 1
		rr := executeToken(t, http.MethodPost, token)
		if len(localTokens) <= MAX_TOKENS {
			assert.Equal(t, rr.Code, http.StatusOK, "Less tokens than limit")
		} else {
			assert.Equal(t, rr.Code, http.StatusInsufficientStorage, "Limitation hit")
		}
	}

	// Cleanup
	returnCodes := make(map[int]int)
	count := 0
	for domain, _ := range localTokens {
		token := CertToken{
			Domain: domain,
		}
		rr := executeToken(t, http.MethodDelete, token)
		if rr.Code == http.StatusOK {
			count++
		} else {
			returnCodes[rr.Code]++
		}
	}
	assert.Equal(t, count, len(localTokens), fmt.Sprintf("Cleanup tokens: %v", returnCodes))
}
