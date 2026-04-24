package models

// Have a struct for the post, i.e what are we expecting
type NoteInput struct {
	Message string `json:"message"`
}

// Data we're storing or sending back it's struct
type Note struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// the error messag and response wrapper
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SuccessResponse struct {
	Status string `json:"status"`
	Data   any    `json:"data"`
}
