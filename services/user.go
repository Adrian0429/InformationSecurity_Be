package services

import (
	"context"
	"errors"

	"github.com/Caknoooo/golang-clean_template/constants"
	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/Caknoooo/golang-clean_template/entities"
	"github.com/Caknoooo/golang-clean_template/helpers"
	"github.com/Caknoooo/golang-clean_template/repository"
	"github.com/Caknoooo/golang-clean_template/utils"
	"github.com/google/uuid"
)

type UserService interface {
	RegisterUser(ctx context.Context, req dto.UserCreateRequest) (dto.UserRegisterResponse, error)
	GetRequestInfo(ctx context.Context, userId string) (dto.UserInfo, error)
	GetAllUser(ctx context.Context) ([]dto.UserResponse, error)
	GetUserById(ctx context.Context, userId string) (dto.UserResponse, error)
	GetUserByEmail(ctx context.Context, email string) (dto.UserResponse, error)
	UpdateStatusIsVerified(ctx context.Context, req dto.UpdateStatusIsVerifiedRequest, adminId string) (dto.UserResponse, error)
	CheckUser(ctx context.Context, email string) (bool, error)
	UpdateUser(ctx context.Context, req dto.UserUpdateRequest, userId string) error
	DeleteUser(ctx context.Context, userId string) error
	Verify(ctx context.Context, email string, password string) (bool, error)
	Upload(ctx context.Context, req dto.MediaRequest, aes dto.EncryptRequest, method string) (dto.MediaResponse, error)

	GetAllMedia(ctx context.Context) ([]dto.MediaInfo, error)
	GetOwnerIDByMediaID(ctx context.Context, path string) (dto.MediaResponse, error)
	GetAESNeeds(ctx context.Context, userId string) (dto.EncryptRequest, error)
}

type userService struct {
	userRepo  repository.UserRepository
	mediaRepo repository.MediaRepository
}

func NewUserService(ur repository.UserRepository, mr repository.MediaRepository) UserService {
	return &userService{
		userRepo:  ur,
		mediaRepo: mr,
	}
}

const PATH = "storage"

func (s *userService) RegisterUser(ctx context.Context, req dto.UserCreateRequest) (dto.UserRegisterResponse, error) {
	email, _ := s.userRepo.CheckEmail(ctx, req.Email)
	if email {
		return dto.UserRegisterResponse{}, dto.ErrEmailAlreadyExists
	}

	symkey := utils.GenerateBytes(16)
	PrivateKey, PublicKey, err := utils.GenerateRSAKeyPair(2048)
	userIV := utils.GenerateBytes(8)

	user := entities.User{
		Name:         req.Name,
		SymmetricKey: symkey,
		PublicKey:    PublicKey,
		PrivateKey:   PrivateKey,
		IV:           userIV,
		Role:         constants.ENUM_ROLE_USER,
		Email:        req.Email,
		Password:     req.Password,
	}

	userResponse, err := s.userRepo.RegisterUser(ctx, user)
	if err != nil {
		return dto.UserRegisterResponse{}, err
	}

	encryptneeds := dto.UserResponse{
		ID: userResponse.ID.String(),
	}

	aes := dto.EncryptRequest{
		SymmetricKey: user.SymmetricKey,
		IV:           user.IV,
	}

	KTPPath, _, TotalTime, err2 := utils.EncryptMedia(req.KTP, aes, PATH, encryptneeds, "AES", "register")
	if err2 != nil {
		return dto.UserRegisterResponse{}, errors.New("Error encrypting/upload KTP")
	}

	err3 := s.userRepo.UpdateKTP(ctx, userResponse.ID, KTPPath)
	if err3 != nil {
		return dto.UserRegisterResponse{}, err3
	}

	return dto.UserRegisterResponse{
		ID:           userResponse.ID.String(),
		Name:         userResponse.Name,
		SymmetricKey: user.SymmetricKey,
		PrivateKey:   user.PrivateKey,
		PublicKey:    user.PublicKey,
		IV:           user.IV,
		Role:         userResponse.Role,
		Email:        userResponse.Email,
		KTP:          KTPPath,
		Totaltime:    TotalTime,
	}, nil
}

func (s *userService) GetAllUser(ctx context.Context) ([]dto.UserResponse, error) {
	users, err := s.userRepo.GetAllUser(ctx)
	if err != nil {
		return nil, dto.ErrGetAllUser
	}

	var userResponse []dto.UserResponse
	for _, user := range users {
		userResponse = append(userResponse, dto.UserResponse{
			ID:         user.ID.String(),
			Name:       user.Name,
			PublicKey:  user.PublicKey,
			PrivateKey: user.PrivateKey,
			IV:         user.IV,
			Role:       user.Role,
			Email:      user.Email,
		})
	}

	return userResponse, nil
}

func (s *userService) UpdateStatusIsVerified(ctx context.Context, req dto.UpdateStatusIsVerifiedRequest, adminId string) (dto.UserResponse, error) {
	admin, err := s.userRepo.GetUserById(ctx, adminId)
	if err != nil {
		return dto.UserResponse{}, dto.ErrUserNotFound
	}

	if admin.Role != constants.ENUM_ROLE_ADMIN {
		return dto.UserResponse{}, dto.ErrUserNotAdmin
	}

	user, err := s.userRepo.GetUserById(ctx, req.UserId)
	if err != nil {
		return dto.UserResponse{}, dto.ErrUserNotFound
	}

	userUpdate := entities.User{
		ID: user.ID,
	}

	err = s.userRepo.UpdateUser(ctx, userUpdate)
	if err != nil {
		return dto.UserResponse{}, dto.ErrUpdateUser
	}

	return dto.UserResponse{
		ID:        user.ID.String(),
		Name:      user.Name,
		PublicKey: user.PublicKey,
		Role:      user.Role,
		Email:     user.Email,
	}, nil
}

func (s *userService) GetUserById(ctx context.Context, userId string) (dto.UserResponse, error) {
	user, err := s.userRepo.GetUserById(ctx, userId)
	if err != nil {
		return dto.UserResponse{}, dto.ErrGetUserById
	}

	return dto.UserResponse{
		ID:           user.ID.String(),
		Name:         user.Name,
		SymmetricKey: user.SymmetricKey,
		PublicKey:    user.PublicKey,
		PrivateKey:   user.PrivateKey,
		Role:         user.Role,
		Email:        user.Email,
		IV:           user.IV,
		KTP:          user.KTP,
	}, nil
}

func (s *userService) GetRequestInfo(ctx context.Context, userId string) (dto.UserInfo, error) {
	user, err := s.userRepo.GetUserById(ctx, userId)
	if err != nil {
		return dto.UserInfo{}, dto.ErrGetUserById
	}

	return dto.UserInfo{
		ID:           user.ID.String(),
		Name:         user.Name,
		SymmetricKey: user.SymmetricKey,
		Email:        user.Email,
	}, nil
}

func (s *userService) GetAESNeeds(ctx context.Context, userId string) (dto.EncryptRequest, error) {
	user, err := s.userRepo.GetUserById(ctx, userId)
	if err != nil {
		return dto.EncryptRequest{}, dto.ErrGetPublicKeyById
	}

	return dto.EncryptRequest{
		SymmetricKey: user.SymmetricKey,
		IV:           user.IV,
	}, nil
}

func (s *userService) GetUserByEmail(ctx context.Context, email string) (dto.UserResponse, error) {
	emails, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return dto.UserResponse{}, dto.ErrGetUserByEmail
	}

	return dto.UserResponse{
		ID:    emails.ID.String(),
		Name:  emails.Name,
		Role:  emails.Role,
		Email: emails.Email,
	}, nil
}

func (s *userService) CheckUser(ctx context.Context, email string) (bool, error) {
	res, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	if res.Email == "" {
		return false, err
	}
	return true, nil
}

func (s *userService) UpdateUser(ctx context.Context, req dto.UserUpdateRequest, userId string) error {
	user, err := s.userRepo.GetUserById(ctx, userId)
	if err != nil {
		return dto.ErrUserNotFound
	}

	userUpdate := entities.User{
		ID:   user.ID,
		Name: req.Name,

		Role:     user.Role,
		Email:    req.Email,
		Password: req.Password,
	}

	err = s.userRepo.UpdateUser(ctx, userUpdate)
	if err != nil {
		return dto.ErrUpdateUser
	}

	return nil
}

func (s *userService) DeleteUser(ctx context.Context, userId string) error {
	user, err := s.userRepo.GetUserById(ctx, userId)
	if err != nil {
		return dto.ErrUserNotFound
	}

	err = s.userRepo.DeleteUser(ctx, user.ID.String())
	if err != nil {
		return dto.ErrDeleteUser
	}

	return nil
}

func (s *userService) Verify(ctx context.Context, email string, password string) (bool, error) {
	res, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return false, dto.ErrUserNotFound
	}

	checkPassword, err := helpers.CheckPassword(res.Password, []byte(password))
	if err != nil {
		return false, dto.ErrPasswordNotMatch
	}

	if res.Email == email && checkPassword {
		return true, nil
	}

	return false, dto.ErrEmailOrPassword
}

func (us *userService) Upload(ctx context.Context, req dto.MediaRequest, encryptionNeeds dto.EncryptRequest, method string) (dto.MediaResponse, error) {
	if req.Media == nil {
		return dto.MediaResponse{}, errors.New("Empty Input!")
	}

	mediaID := uuid.New()
	userId, err := uuid.Parse(req.UserID)
	if err != nil {
		return dto.MediaResponse{}, errors.New("error parsing string to uid")
	}

	user, err := us.GetUserById(ctx, req.UserID)
	if err != nil {
		return dto.MediaResponse{}, errors.New("error getting user")
	}

	mediaPath, getwithkey, TotalTime, err := utils.EncryptMedia(req.Media, encryptionNeeds, PATH, user, method, "")
	if err != nil {
		return dto.MediaResponse{}, err
	}

	requestUrl := utils.RequestURL(userId)

	Media := entities.Media{
		ID:       mediaID,
		Filename: req.Media.Filename,
		Path:     mediaPath,
		UserID:   userId,
		DownKey:  getwithkey,
		Request:  requestUrl,
	}

	Media, err = us.mediaRepo.Upload(ctx, Media)
	if err != nil {
		return dto.MediaResponse{}, err
	}

	res := dto.MediaResponse{
		ID:       Media.ID.String(),
		Filename: Media.Filename,
		Time:     TotalTime,
		Path:     Media.Path,
		DownKey:  Media.DownKey,
		Request:  Media.Request,
		UserID:   Media.UserID,
	}

	return res, nil
}

func (s *userService) GetOwnerIDByMediaID(ctx context.Context, path string) (dto.MediaResponse, error) {
	user, err := s.mediaRepo.GetMedia(ctx, path)
	if err != nil {
		return dto.MediaResponse{}, dto.ErrOwnerIDByMediaPath
	}

	return dto.MediaResponse{
		UserID: user.UserID,
	}, nil
}

func (s *userService) GetAllMedia(ctx context.Context) ([]dto.MediaInfo, error) {
	medias, err := s.mediaRepo.GetAllMedia(ctx)
	if err != nil {
		return nil, dto.ErrGetAllMedia
	}

	var userResponse []dto.MediaInfo
	for _, media := range medias {
		user, err := s.GetUserById(ctx, media.UserID.String())
		if err != nil {
			return nil, dto.ErrGetAllMedia
		}
		userResponse = append(userResponse, dto.MediaInfo{
			ID:        media.ID.String(),
			Filename:  media.Filename,
			Path:      media.Path,
			Name:      user.Name,
			DownKey:   media.DownKey,
			Request:   media.Request,
			PublicKey: user.PublicKey,
		})
	}

	return userResponse, nil
}
