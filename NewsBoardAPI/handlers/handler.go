package handlers

import (
	"boards/db"
	"boards/middleware"
	"boards/models"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var u models.UserInput
	// Decode the Inputs
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return

	}

	// validate the password, email username is ok
	ok := passwordOk(u.Password)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Password length is 8 minimum and must contain a digit",
		})
		return
	}
	ok = usernameOk(u.Username)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Username should be between 3 and 20 characters and contains only letters digits and underscore",
		})
		return
	}
	ok = emailOk(u.Email)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "invalid email",
		})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return

	}

	// Input the user into the struct
	response := models.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Username:  u.Username,
		Password:  string(hash),
		Email:     u.Email,
		Verified:  false,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// send to the database
	_, err = db.DB.Exec(`
        INSERT INTO users 
        (id, username, password, email, verified, created_at)
        VALUES ($1,$2,$3,$4,$5,$6)`,
		response.ID, response.Username, response.Password, response.Email, response.Verified, response.CreatedAt,
	)

	if err != nil {
		// check if it's a database Error
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Username already exist in the database ",
			})
			return
		}

		// return the error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Failed to save User",
			"error":   err.Error(),
		})
		return
	}

	// DELETE ANY EXISTING TOKEN FOR THE USER
	_, err = db.DB.Exec("DELETE FROM tokens WHERE user_id = $1", response.ID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// GENERATE TOKEN AND SET EXPIRY TO 24 HOURS FROM THE NOW
	tk := generateEmailToken()

	token := models.Token{
		TokenString: tk,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	// INSERT TOKEN INTO STRUCT AND THEN DB TABLE
	_, err = db.DB.Exec(`
        INSERT INTO tokens 
        (user_id, token, expires_at)
        VALUES ($1,$2,$3)`,
		response.ID, token.TokenString, token.ExpiresAt,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// SEND VERIFICATION LINK
	email := u.Email
	subject := "Verify Your Account"
	link := os.Getenv("BASE_URL") + "/api/verify?token=" + tk
	body := "Click this link to verify your email: " + link

	err = sendEmail(email, subject, body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// RESPONSE
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": "User created Successfully",
	})
}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	var u models.UserInput
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return

	}

	if u.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "needs a username",
		})
		return
	}

	if u.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Input a password",
		})
		return
	}

	// check the database for the username
	var p models.User
	err = db.DB.QueryRow(`
        SELECT id, username, password, created_at
        FROM users WHERE LOWER(username) = LOWER($1)`, u.Username).
		Scan(&p.ID, &p.Username, &p.Password, &p.CreatedAt)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Username not found",
		})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	hash := []byte(p.Password)
	err = bcrypt.CompareHashAndPassword(hash, []byte(u.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Wrong Password",
		})
		return
	}

	tokenString, err := middleware.GenerateToken(p.ID, p.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"token":  tokenString,
	})
}

func CreatePost(w http.ResponseWriter, r *http.Request) {
	// get the values from the context
	userData, ok := r.Context().Value(middleware.UserCtxKey).(middleware.UserContext)
	if !ok {
		// Handle error if data isn't there
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "No data found in the context",
		})
		return
	}

	ok = urlOk(userData.URL)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Invalid Url provided",
		})
		return
	}

	metadataCh := make(chan models.JsonResult, 1)
	go func() {
		resp, err := GetMetadata(userData.URL)
		metadataCh <- models.JsonResult{
			Data: resp,
			Err:  err,
		}
	}()
	resp := <-metadataCh

	if resp.Err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": resp.Err.Error(),
		})
		return
	}

	// get the datails fro the resp and send it
	response := models.Post{
		ID:          uuid.Must(uuid.NewV7()).String(),
		AuthorID:    userData.ID,
		Author:      userData.Username,
		Title:       resp.Data.Title,
		Description: &resp.Data.Description,
		SiteName:    resp.Data.SiteName,
		Domain:      &resp.Data.Domain,
		URL:         userData.URL,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// send to the database
	_, err := db.DB.Exec(`
        INSERT INTO posts
        (id, author_id, author, title, description, site_name, domain, url, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		response.ID, response.AuthorID, response.Author, response.Title,
		response.Description, response.SiteName, response.Domain, response.URL, response.CreatedAt,
	)

	if err != nil {
		// check if it's a database Error
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Post already exist in the database ",
			})
			return
		}

		// return the error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Failed to save User",
			"error":   err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   response,
	})

}

// TODO: Remove the mock data before deployment

func GetPostById(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// ususally 3 check when dealing with id
	// First Check
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "id not specified",
		})
		return
	}

	row := db.DB.QueryRow(
		`SELECT id, author, author_id, title, description, site_name, domain, url, created_at 
		FROM posts WHERE id = $1`, id)

	var resp models.Post
	err := row.Scan(&resp.ID, &resp.Author, &resp.AuthorID, &resp.Title, &resp.Description,
		&resp.SiteName, &resp.Domain, &resp.URL, &resp.CreatedAt)

	// second Check, if the error is no error
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Post with that id not found in the db",
		})
		return
	}

	// Lastly check if there is other database error
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
	}

	// return it.
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   resp,
	})
}

func GetPosts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	author := strings.ToLower(query.Get("author"))

	// 1. Define the base query and arguments
	sqlQuery := "SELECT id, author_id, author, title, description, site_name, domain, url, created_at FROM posts"
	var args []interface{}

	// 2. Add dynamic filtering
	if author != "" {
		sqlQuery += " WHERE LOWER(author) = $1"
		args = append(args, author)
	}

	// 3. Execute the query
	rows, err := db.DB.Query(sqlQuery, args...)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Failed to fetch posts",
			"error":   err.Error(),
		})
		return
	}
	defer rows.Close()

	// 4. Loop through the rows and save to a slice
	var posts []models.Post = []models.Post{}
	for rows.Next() {
		var p models.Post
		// Scan must match the order of columns in your SELECT statement
		err := rows.Scan(
			&p.ID,
			&p.AuthorID,
			&p.Author,
			&p.Title,
			&p.Description,
			&p.SiteName,
			&p.Domain,
			&p.URL,
			&p.CreatedAt,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Error scanning post data",
				"error":   err.Error(),
			})
			return
		}
		posts = append(posts, p)
	}

	// Check for errors encountered during iteration
	if err = rows.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Row iteration error",
			"error":   err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   posts,
	})
}

// Request Clinet and function
var client = &http.Client{Timeout: 15 * time.Second}

func GetMetadata(url string) (models.MetadataResponse, error) {
	// make the request
	link := fmt.Sprintf("https://jsonlink.io/api/extract?url=%s&api_key=%s", url, os.Getenv("JSONLINK_API_KEY"))
	fmt.Println("Fetching:", link)
	resp, err := client.Get(link)
	if err != nil {
		return models.MetadataResponse{}, err
	}
	defer resp.Body.Close()

	// Additional check
	if resp.StatusCode != http.StatusOK {
		return models.MetadataResponse{}, fmt.Errorf("metadata API returned status %d", resp.StatusCode)
	}

	var result models.MetadataResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return models.MetadataResponse{}, err
	}

	return result, nil
}

// func GetMetadata(url string) (models.MetadataResponse, error) {
// 	// temporary mock for local testing
// 	return models.MetadataResponse{
// 		Title:       "Test Article",
// 		Description: "Test description",
// 		SiteName:    "BBC",
// 		Domain:      "bbc.com",
// 	}, nil
// }

func usernameOk(s string) bool {
	runes := []rune(s)
	if len(runes) < 3 || len(runes) > 20 {
		return false
	}

	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}

	return true
}

func passwordOk(s string) bool {
	runes := []rune(s)
	if len(runes) < 8 {
		return false
	}

	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func urlOk(s string) bool {
	parsed, err := url.Parse(s)
	if err == nil {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return false
		}

		if parsed.Host != "" {
			return true
		}
	}

	return false
}

func emailOk(s string) bool {
	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}

	return true
}

func sendEmail(to, subject, msg string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SENDER_ADDRESS"))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", msg)

	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("SENDER_ADDRESS"), os.Getenv("APP_PASSWORD"))
	return d.DialAndSend(m)
}

func generateEmailToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)

}

const tableSchema = `
    CREATE TABLE IF NOT EXISTS tokens (
        user_id UUID REFERENCES users(id),
        token VARCHAR NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL
    );`
