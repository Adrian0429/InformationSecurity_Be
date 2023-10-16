package dto

import (
	"errors"
	"mime/multipart"
)

const (
	// Failed
	MESSAGE_FAILED_GET_DATA_FROM_BODY      = "failed get data from body"
	MESSAGE_FAILED_REGISTER_USER           = "failed create user"
	MESSAGE_FAILED_GET_LIST_USER           = "failed get list user"
	MESSAGE_FAILED_GET_USER_TOKEN          = "failed get user token"
	MESSAGE_FAILED_TOKEN_NOT_VALID         = "token not valid"
	MESSAGE_FAILED_TOKEN_NOT_FOUND         = "token not found"
	MESSAGE_FAILED_GET_USER                = "failed get user"
	MESSAGE_FAILED_GET_KEY                 = "failed get key user"
	MESSAGE_FAILED_LOGIN                   = "failed login"
	MESSAGE_FAILED_WRONG_EMAIL_OR_PASSWORD = "wrong email or password"
	MESSAGE_FAILED_UPDATE_USER             = "failed update user"
	MESSAGE_FAILED_DELETE_USER             = "failed delete user"
	MESSAGE_FAILED_PROSES_REQUEST          = "failed proses request"
	MESSAGE_FAILED_DENIED_ACCESS           = "denied access"
	MESSAGE_FAILED_DECRYPT                 = "decryption failed"
	MESSAGE_FAILED_AUTHENTIFICATION        = "You do not have permission to access this file."
	MESSAGE_FAILED_GET_FILE                = "failed get file"
	MESSAGE_FAILED_RENAME_FILE			   = "failed to rename file"
	// Success
	MESSAGE_SUCCESS_REGISTER_USER = "success create user"
	MESSAGE_SUCCESS_GET_LIST_USER = "success get list user"
	MESSAGE_SUCCESS_GET_USER      = "success get user"
	MESSAGE_SUCCESS_LOGIN         = "success login"
	MESSAGE_SUCCESS_UPDATE_USER   = "success update user"
	MESSAGE_SUCCESS_DELETE_USER   = "success delete user"
)

var (
	ErrCreateUser         = errors.New("failed to create user")
	ErrGetAllUser         = errors.New("failed to get all user")
	ErrGetUserById        = errors.New("failed to get user by id")
	ErrGetKeyById         = errors.New("failed to get Key and IV by id")
	ErrGetUserByEmail     = errors.New("failed to get user by email")
	ErrEmailAlreadyExists = errors.New("email already exist")
	ErrUpdateUser         = errors.New("failed to update user")
	ErrUserNotAdmin       = errors.New("user not admin")
	ErrUserNotFound       = errors.New("user not found")
	ErrDeleteUser         = errors.New("failed to delete user")
	ErrPasswordNotMatch   = errors.New("password not match")
	ErrEmailOrPassword    = errors.New("wrong email or password")
	ErrAccountNotVerified = errors.New("account not verified")
	ErrOwnerIDByMediaPath = errors.New("failed to get OwnerID by Media Path")
	ErrGetAllMedia        = errors.New("failed to get all Media")
)

type (
	UserCreateRequest struct {
		Name     string                `json:"name" form:"name"`
		Email    string                `json:"email" form:"email"`
		Password string                `json:"password" form:"password"`
		KTP      *multipart.FileHeader `json:"ktp" form:"ktp"`
	}

	UserResponse struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Key   string `json:"key"`
		IV    string `jsgon:"iv"`
		Role  string `json:"role"`
		Email string `json:"email"`
		KTP   string `json:"ktp_path"`
		Totaltime string `json:"total_time"`
	}

	EncryptRequest struct {
		Key string `json:"key"`
		IV  string `jsgon:"iv"`
	}

	UserUpdateRequest struct {
		Name string `json:"name" form:"name"`

		Email    string `json:"email" form:"email"`
		Password string `json:"password" form:"password"`
	}

	UserLoginRequest struct {
		Email    string `json:"email" form:"email" binding:"required"`
		Password string `json:"password" form:"password" binding:"required"`
	}

	UpdateStatusIsVerifiedRequest struct {
		UserId string `json:"user_id" form:"user_id" binding:"required"`
	}
)
