package middleware

import (
	"boards/models"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MyClaim struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type UserContext struct {
	ID       string
	Username string
	URL      string
}

type contextKey string

const (
	UserCtxKey contextKey = "user_data"
)

func GenerateToken(id, username string) (string, error) {
	// 1. Create the claims
	claims := MyClaim{
		ID:               id,
		Username:         username,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour))},
	}

	// 2. Create the token using the HS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 3. Sign the token with our secret key
	mySecret := []byte(os.Getenv("JWT_SECRET"))
	tokenString, err := token.SignedString(mySecret)

	return tokenString, err
}

func ValidateToken(tokenString string) (*MyClaim, error) {
	mySecret := []byte(os.Getenv("JWT_SECRET"))

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &MyClaim{}, func(t *jwt.Token) (any, error) {
		// Ensure the signing method is what we expect
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return mySecret, nil
	})

	// Check if token is valid and extract claims
	if claims, ok := token.Claims.(*MyClaim); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next(w, r)
	}
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		h := r.Header.Get("Authorization")
		if h == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Your aren't authorized",
			})
			return
		}

		tokenString := strings.TrimPrefix(h, "Bearer ")
		claims, err := ValidateToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}

		var input models.PostInput
		err = json.NewDecoder(r.Body).Decode(&input)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}

		if input.Url == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "No url specified",
			})
			return
		}

		// values added to the context
		UserData := UserContext{
			ID:       claims.ID,
			Username: claims.Username,
			URL:      input.Url,
		}

		// putting a value in (middleware)
		ctx := context.WithValue(r.Context(), UserCtxKey, UserData)
		r = r.WithContext(ctx)
		next(w, r)

	}
}
