package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Structs
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type RegisterResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type contextKey string

const usernameKey contextKey = "username"

// Storage
var db = map[string][]byte{}

// handlers
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var u User

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return

	}

	if u.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "need a username",
		})
		return
	}

	if u.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "Input a password",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return

	}

	db[u.Username] = hash
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{
		Status:  "success",
		Message: "User created Successfully",
	})

}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return

	}

	if u.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "needs a username",
		})
		return
	}

	if u.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "Input a password",
		})
		return
	}

	username := u.Username
	hash, ok := db[username]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "User no in database",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(u.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: "Wrong Password",
		})
		return
	}

	tokenString, err := GenerateToken(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"token":  tokenString,
	})

}

func GetMe(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value(usernameKey).(string)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"Message": fmt.Sprintf("%v verified", username),
	})

}

func main() {
	// godotenv.Load()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Handler and Routing
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", corsMiddleware(RegisterUser))
	mux.HandleFunc("POST /api/login", corsMiddleware(UserLogin))
	mux.HandleFunc("GET /api/me", corsMiddleware(authMiddleware(GetMe)))

	// Server
	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Server running on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")

		if h == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Status:  "error",
				Message: "Your aren't authorized",
			})
			return
		}

		tokenString := strings.TrimPrefix(h, "Bearer ")

		claims, err := ValidateToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Status:  "error",
				Message: err.Error(),
			})
			return
		}

		username := claims.Username

		// putting a value in (middleware)
		ctx := context.WithValue(r.Context(), usernameKey, username)
		r = r.WithContext(ctx)
		next(w, r)

	}
}

// this is your payload you give what you want
type MyClaim struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(username string) (string, error) {
	// 1. Create the claims
	claims := MyClaim{
		username,
		jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour))},
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
