package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

const goodKID = "aRandomKeyID"

var goodPrivKey *rsa.PrivateKey
var expiredPrivKey *rsa.PrivateKey

func main() {
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory: %v", err)
	}

	dbPath := currentDir + "/totally_not_my_privateKeys.db"
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	createTableStmt := `CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`
	_, err = db.Exec(createTableStmt)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}

	genKeys(db)

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler(db))
	http.HandleFunc("/auth", AuthHandler(db))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateAndSavePrivateKey(filename string, exp int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	err = ioutil.WriteFile(filename, pem.EncodeToMemory(pemBlock), 0644)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func genKeys(db *sql.DB) {
	var err error
	goodPrivKey, err = generateAndSavePrivateKey("good_key.pem", 3600)
	if err != nil {
		log.Fatalf("Error generating and saving good private key: %v", err)
	}

	expiredPrivKey, err = generateAndSavePrivateKey("expired_key.pem", -3600)
	if err != nil {
		log.Fatalf("Error generating and saving expired private key: %v", err)
	}

	saveKeyToDB(db, goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	saveKeyToDB(db, expiredPrivKey, time.Now().Add(-1*time.Hour).Unix())
}

func saveKeyToDB(db *sql.DB, key *rsa.PrivateKey, exp int64) {
	keyBytes := encodePrivateKeyToBytes(key)
	_, err := db.Exec("INSERT INTO keys(key, exp) VALUES (?, ?)", keyBytes, exp)
	if err != nil {
		log.Printf("Error saving key to the database: %v", err)
	}
}

func encodePrivateKeyToBytes(key *rsa.PrivateKey) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(pemBlock)
}

func decodeBytesToPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, errors.New("Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func AuthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var (
			signingKey *rsa.PrivateKey
			keyID      string
			exp        int64
		)

		signingKey = goodPrivKey
		keyID = goodKID
		exp = time.Now().Add(1 * time.Hour).Unix()

		if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
			signingKey = expiredPrivKey
			keyID = "expiredKeyId"
			exp = time.Now().Add(-1 * time.Hour).Unix()
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"exp": exp,
		})
		token.Header["kid"] = keyID
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(signedToken))
	}
}

func JWKSHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		base64URLEncode := func(b *big.Int) string {
			return base64.RawURLEncoding.EncodeToString(b.Bytes())
		}

		rows, err := db.Query("SELECT key FROM keys WHERE exp > ?", time.Now().Unix())
		if err != nil {
			http.Error(w, "failed to retrieve keys from the database", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var keys []JWK
		for rows.Next() {
			var keyBytes []byte
			err := rows.Scan(&keyBytes)
			if err != nil {
				log.Printf("Error scanning key from database: %v", err)
				continue
			}

			privateKey, err := decodeBytesToPrivateKey(keyBytes)
			if err != nil {
				log.Printf("Error decoding key from bytes: %v", err)
				continue
			}

			keys = append(keys, JWK{
				KID:       goodKID,
				Algorithm: "RS256",
				KeyType:   "RSA",
				Use:       "sig",
				N:         base64URLEncode(privateKey.N),
				E:         base64URLEncode(big.NewInt(int64(privateKey.E))),
			})
		}

		resp := JWKS{Keys: keys}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}
