package middleware

import (
	"boards/models"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
	limit    int
	window   time.Duration
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

// Rate Limiter
func (r *RateLimiter) Allow(clientId string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	val, _ := r.requests[clientId]

	// set the threshold. Now going back window seconds(which is whatever we se)
	threshold := time.Now().Add(-r.window)
	filtered := []time.Time{}
	for _, v := range val {
		if v.After(threshold) {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) >= r.limit {
		return false
	}

	val = append(val, time.Now()) // add the time now that the person is making request
	r.requests[clientId] = val

	return true
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	var rl RateLimiter

	rl.requests = make(map[string][]time.Time)
	rl.limit = limit
	rl.window = window

	return &rl
}

func RateLimiterMiddleWare(limit int, window time.Duration) func(http.HandlerFunc) http.HandlerFunc {
	rl := NewRateLimiter(limit, window)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// get the ip address from the request
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)

			// check if it can make request
			ok := rl.Allow(ip)
			if !ok {
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "error",
					"message": "Too many Requests",
				})
				return
			}

			next(w, r)
		}
	}
}
