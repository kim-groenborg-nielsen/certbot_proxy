package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"
)

type CertToken struct {
	Domain string `json:"domain"`
	Token string `json:"token"`
	Validation string `json:"validation"`
}

// Make map of certificat tokens where the key is the domain
var certTokens = make(map[string]CertToken)

var tokenPostPath = os.Getenv("TOKEN_POST_PATH")
var uploadPath = os.Getenv("UPLOAD_PATH")
const acmeChallangePath = "/.well-known/acme-challenge/"
const MAX_TOKENS = 10000

const MAX_UPLOAD_FILE_SIZE = 1024 * 1014

func main() {
	if tokenPostPath == "" {
		tokenPostPath = "/token_poster/"
	}
	if uploadPath == "" {
		ex, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		uploadPath = path.Dir(ex) + "/upload"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "4080"
		log.Printf("Defaulting to port %s", port)
	}

	//http.HandleFunc("/", indexHandler)
	http.HandleFunc(acmeChallangePath, acmeChallangeHandler)
	http.HandleFunc(tokenPostPath, acmeTokenHandler)
	http.HandleFunc(tokenPostPath + "upload", fileUploadHandler)

	log.Printf("Upload file path %s", uploadPath)
	log.Printf("Token post path %s", tokenPostPath)
	log.Printf("Listening on port %s", port)
	log.Printf("Open http://localhost:%s in the browser", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%s", port), nil))
}

func getIp(r *http.Request) string {
	fwd := r.Header.Get("X-FORWARDED-FOR")
	if fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

func acmeChallangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ip := getIp(r)
		log.Printf("Request token for %s from %s", r.Host, ip)
		if token, ok := certTokens[r.Host]; ok {
			if r.URL.Path == acmeChallangePath+token.Token {
				log.Printf("Return token for %s to %s", r.Host, ip)
				_, err := fmt.Fprintf(w, token.Validation)
				if err != nil {
					http.Error(w, "Internal error", http.StatusInternalServerError)
				}
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func acmeTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := &CertToken{}
	if r.Body == nil {
		http.Error(w, "Bad json request", http.StatusBadRequest)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(token); err != nil {
		http.Error(w, "Bad json request", http.StatusBadRequest)
		return
	}
	ip := getIp(r)
	switch r.Method {
	case http.MethodPost:
		if token.Domain == "" || token.Validation == "" || token.Token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(certTokens) >= MAX_TOKENS {
			log.Printf("Hits token limitation of %d, someone is proberly doing DoS, maybe from %s", MAX_TOKENS, ip)
			w.WriteHeader(http.StatusInsufficientStorage)
		}
		log.Printf("Set token for %s from %s", token.Domain, ip)
		certTokens[token.Domain] = *token
		return
	case http.MethodDelete:
		log.Printf("Delete token for %s from %s", token.Domain, ip)
		delete(certTokens, token.Domain)
		return
	}
	log.Printf("%s method not allowed from %s", r.Method, ip)
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func writeUploadFile(fileHeader *multipart.FileHeader, domain string) (int, error) {
	if fileHeader.Size > MAX_UPLOAD_FILE_SIZE {
		return http.StatusBadRequest, fmt.Errorf("Size of %s is larger than %d", fileHeader.Filename, MAX_UPLOAD_FILE_SIZE)
	}

	file, err := fileHeader.Open()
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Upload: Error opening upload file %s: %v", fileHeader.Filename, err)
	}
	defer file.Close()

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil {
		return http.StatusInternalServerError, err
	}

	fileType := http.DetectContentType(buffer)
	log.Printf("Upload file %s with type %s", fileHeader.Filename, fileType)

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Upload: Cannot seek to start of %s: %v", fileHeader.Filename ,err)
	}

	domainUpload := path.Join(uploadPath, domain)
	if err := os.MkdirAll(domainUpload, os.ModePerm); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Upload: Unable to create %s: %v", domainUpload, err)
	}

	fullUploadPath := path.Join(domainUpload, fileHeader.Filename)
	if strings.Contains(fullUploadPath, "..") {
		return http.StatusBadRequest, fmt.Errorf("Upload: Invalid upload fullpath: %s", fullUploadPath)
	}

	f, err := os.Create(fullUploadPath)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Upload: Cannot create %s", fullUploadPath)
	}
	defer f.Close()

	if _, err := io.Copy(f, file); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("Upload: Error writing %s: %v", fullUploadPath, err)
	}
	log.Printf("%s uploaded", fullUploadPath)
	return http.StatusOK, nil
}

func fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "File upload to big", http.StatusBadRequest)
			return
		}

		domains := r.MultipartForm.Value["domain"]
		if len(domains) != 1 {
			log.Print("Upload: Domain should be given once, and only once")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		domain := domains[0]
		if domain == "" {
			log.Printf("Upload: No domain found in data")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.Contains(domain, "..") || !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
			log.Printf("Upload: Invalid domain: '%s'", domain)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		files := r.MultipartForm.File["file"]
		for _, fileHeader := range files {
			if status, err := writeUploadFile(fileHeader, domain); err != nil {
				log.Printf("%v", err)
				w.WriteHeader(status)
				return
			}
		}
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
