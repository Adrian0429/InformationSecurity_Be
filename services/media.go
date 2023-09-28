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

func (ms *mediaService) Upload(ctx context.Context, req dto.MediaRequest) (dto.MediaResponse, error) {
	if req.Media == nil {
		return dto.MediaResponse{}, errors.New("Empty Input!")
	}

	base64encrypted, err := utils.EncodeBase64(req.Media)
	if err != nil {
		return dto.MediaResponse{}, errors.New("error encrypting to base64!")
	}

	mediaId := uuid.New()
	_ = utils.SaveImage(base64encrypted, PATH, mediaId.String())
	mediaName := utils.GenerateFilename(PATH, mediaId.String())

	err = utils.SaveEncrypted(base64encrypted, PATH, mediaId.String())
	if err != nil {
		return dto.MediaResponse{}, err
	}

	Media := entities.Media{
		ID:       mediaId,
		Filename: req.Media.Filename,
		Path:     mediaName,
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
