package services

import (
	"context"
	"errors"

	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/Caknoooo/golang-clean_template/entities"
	"github.com/Caknoooo/golang-clean_template/repository"
	"github.com/Caknoooo/golang-clean_template/utils"
	"github.com/google/uuid"
)

type (
	MediaService interface {
		Upload(ctx context.Context, req dto.MediaRequest) (dto.MediaResponse, error)
	}

	mediaService struct {
		mediaRepository repository.MediaRepository
	}
)

func NewMediaService(mr repository.MediaRepository) MediaService {
	return &mediaService{
		mediaRepository: mr,
	}
}

const PATH = "storage"
const KEY = "6c469546af4c7ef553db67a9f9c08e11"

func (ms *mediaService) Upload(ctx context.Context, req dto.MediaRequest) (dto.MediaResponse, error) {
	if req.Media == nil {
		return dto.MediaResponse{}, errors.New("Empty Input!")
	}

	mediaID := uuid.New()

	// key, err := utils.GenerateAESKey()
	// if err != nil {
	// 	return dto.MediaResponse{}, errors.New("failed generating new key")
	// }

	key := []byte(KEY)
	mediaPath, err := utils.EncryptMedia(req.Media, key, PATH)
	if err != nil {
		return dto.MediaResponse{}, err
	}

	Media := entities.Media{
		ID:       mediaID,
		Filename: mediaPath,
		Path:     PATH + req.Media.Filename + ".enc",
	}

	Media, err = ms.mediaRepository.Upload(ctx, Media)
	if err != nil {
		return dto.MediaResponse{}, err
	}

	res := dto.MediaResponse{
		ID:       Media.ID.String(),
		Filename: Media.Filename,
		Path:     Media.Path,
	}

	return res, nil
}
