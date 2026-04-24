package main

import (
	"log"
	"net/http"
	"os"

	"boards/db"
	"boards/handlers"
	"boards/middleware"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("No Database url Specified")
	}

	db.Connect(connStr)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", middleware.CorsMiddleware(handlers.RegisterUser))
	mux.HandleFunc("POST /api/login", middleware.CorsMiddleware(handlers.UserLogin))
	mux.HandleFunc("POST /api/posts", middleware.CorsMiddleware(middleware.AuthMiddleware(handlers.CreatePost)))
	mux.HandleFunc("GET /api/posts", middleware.CorsMiddleware(handlers.GetPosts))
	mux.HandleFunc("GET /api/posts/{id}", middleware.CorsMiddleware(handlers.GetPostById))

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("No Port Specified")
	}

	log.Printf("Server running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
