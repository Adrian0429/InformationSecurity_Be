package dto

import (
	"mime/multipart"
)

var (
	ErrEmptyFile = "empty file"
)

type (
	MediaRequest struct {
		Media *multipart.FileHeader `json:"media" form:"media"`
	}

	MediaResponse struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
	}
)
