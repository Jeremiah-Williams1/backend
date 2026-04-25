package models

import "time"

type UserInput struct {
	Username string `json:"username"`
	Password string
	Email    string `json:"email"`
}

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"-"`
	Email     string `json:"email"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

type Token struct {
	TokenString string
	ExpiresAt   time.Time
}
type Post struct {
	ID          string  `json:"id"`
	AuthorID    string  `json:"author_id"`
	Author      string  `json:"author"`
	Title       string  `json:"title"`
	Description *string `json:"description"`
	SiteName    string  `json:"site_name"`
	Domain      *string `json:"domain"`
	URL         string  `json:"url"`
	CreatedAt   string  `json:"created_at"`
}

type MetadataResponse struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	SiteName    string `json:"site_name"`
	Domain      string `json:"domain"`
	Url         string `json:"url"`
}

type PostInput struct {
	Url string `json:"url"`
}

type JsonResult struct {
	Data MetadataResponse
	Err  error
}
