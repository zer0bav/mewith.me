package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type JWTPayload struct {
	Username string `json:"u"`
	IsAdmin  bool   `json:"a"`
	Exp      int64  `json:"exp"`
}

var jwtSecret []byte

func InitSecurity() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = ""
	}
	jwtSecret = []byte(secret)
}

func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func CreateJWT(username string, isAdmin bool) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`
	headerEnc := base64.RawURLEncoding.EncodeToString([]byte(header))
	payload := JWTPayload{Username: username, IsAdmin: isAdmin, Exp: time.Now().Add(24 * time.Hour).Unix()}
	payloadBytes, _ := json.Marshal(payload)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)
	data := headerEnc + "." + payloadEnc
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return data + "." + signature, nil
}

func VerifyJWT(tokenString string) (*JWTPayload, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	data := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(data))
	expectedSig := h.Sum(nil)
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload JWTPayload
	json.Unmarshal(payloadBytes, &payload)
	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("expired")
	}
	return &payload, nil
}

func GetUserFromRequest(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return User{}, false
	}
	claims, err := VerifyJWT(cookie.Value)
	if err != nil {
		return User{}, false
	}
	var user User
	if err := DB.Where("username = ?", claims.Username).First(&user).Error; err != nil {
		return User{}, false
	}
	return user, true
}
