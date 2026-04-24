package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
	limit    int
	window   time.Duration
}

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

func health(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "login successful",
	})

}

func rateLimiterMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	rl := NewRateLimiter(5, 60*time.Second)

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

func main() {
	// godotenv.Load()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Handler and Routing
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", rateLimiterMiddleWare(Login))
	mux.HandleFunc("GET /health", health)

	// Server
	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Server running on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
