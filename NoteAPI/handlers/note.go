package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"notes-api/models"
	"time"
)

var notes = map[string]models.Note{}

func CollectNote(w http.ResponseWriter, r *http.Request) {
	var note models.NoteInput
	err := json.NewDecoder(r.Body).Decode(&note)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return
	}

	if note.Message == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: "No content found in the Post",
		})
		return
	}

	var ter models.Note

	id := fmt.Sprintf("%d", time.Now().UnixNano())

	ter.ID = id
	ter.Message = note.Message
	ter.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	notes[ter.ID] = ter

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.SuccessResponse{
		Status: "success",
		Data:   ter,
	})
}

func EditSingleNote(w http.ResponseWriter, r *http.Request) {
	// get the ID
	id := r.PathValue("id")

	// check if it's in the note if no return Error
	val, ok := notes[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: "Note with that ID isn't available",
		})
		return
	}

	// read the body from the request
	var result models.NoteInput
	err := json.NewDecoder(r.Body).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return
	}

	// extract the message
	msg := result.Message

	if msg == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: "No content found to Edit",
		})
		return
	}

	val.Message = msg
	val.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	notes[id] = val

	// set status code and send
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode((models.SuccessResponse{
		Status: "success",
		Data:   val,
	}))

}

func GetAllNote(w http.ResponseWriter, r *http.Request) {
	// Have your response variable decleared, it should be a list of notes
	allnotes := make([]models.Note, 0)

	// loop through the notes and append the note to the variable declared above
	for _, v := range notes {
		allnotes = append(allnotes, v)
	}

	// Status Code
	w.WriteHeader(http.StatusOK)

	// write the respons back to our Client
	json.NewEncoder(w).Encode(models.SuccessResponse{
		Status: "success",
		Data:   allnotes,
	})

}

func GetSingleNote(w http.ResponseWriter, r *http.Request) {
	// get the ID
	id := r.PathValue("id")

	// check if it's in the note if no return Error
	val, ok := notes[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: "Note with that ID isn't available",
		})
		return
	}

	// set Status
	w.WriteHeader(http.StatusOK)

	// encode and send response back
	json.NewEncoder(w).Encode(models.SuccessResponse{
		Status: "success",
		Data:   val,
	})

}

func DeleteSingleNote(w http.ResponseWriter, r *http.Request) {
	// get the id
	id := r.PathValue("id")

	// check if that id is in the notes
	_, ok := notes[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(models.ErrorResponse{
			Status:  "error",
			Message: "Note with that ID isn't available",
		})
		return
	}

	// Delete id from notes
	delete(notes, id)

	// set Status
	w.WriteHeader(http.StatusOK)

	// encode and send response back
	json.NewEncoder(w).Encode(models.SuccessResponse{
		Status: "success",
		Data:   fmt.Sprintf("Note with id %v was deleted successfully", id),
	})

}
