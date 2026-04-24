package main

import (
	"net/http"
	"notes-api/handlers"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Handler and Routing
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/notes/{id}", corsMiddleware(handlers.DeleteSingleNote))
	mux.HandleFunc("GET /api/notes/{id}", corsMiddleware(handlers.GetSingleNote))
	mux.HandleFunc("GET /api/notes", corsMiddleware(handlers.GetAllNote))
	mux.HandleFunc("POST /api/notes", corsMiddleware(handlers.CollectNote))
	mux.HandleFunc("PUT /api/notes/{id}", corsMiddleware(handlers.EditSingleNote))

	// Server
	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	srv.ListenAndServe()
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next(w, r)
	}
}
