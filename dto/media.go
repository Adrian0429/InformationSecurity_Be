package dto

import (
	"mime/multipart"

	"github.com/google/uuid"
)

var (
	ErrEmptyFile = "empty file"
)

type (
	MediaRequest struct {
		Media  *multipart.FileHeader `json:"media" form:"media"`
		UserID string                `json:"UID"`
	}

	MediaCreate struct {
		ID       string    `json:"id"`
		Filename string    `json:"filename"`
		Path     string    `json:"path"`
		UserID   uuid.UUID `json:"UID"`
	}

	MediaResponse struct {
		ID       string    `json:"id"`
		Filename string    `json:"filename"`
		Path     string    `json:"path"`
		Time     string    `json:"time"`
		
		UserID   uuid.UUID `json:"UID"`
	}

	MediaInfo struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
		Name     string `json:"name"`
	}
)
