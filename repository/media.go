package repository

import (
	"context"

	"github.com/Caknoooo/golang-clean_template/entities"
	"gorm.io/gorm"
)

type (
	MediaRepository interface {
		Upload(ctx context.Context, media entities.Media) (entities.Media, error)
		GetMedia(ctx context.Context, mediaId string) (entities.Media, error)
	}

	mediaRepository struct {
		db *gorm.DB
	}
)

func NewMediaRepository(db *gorm.DB) *mediaRepository {
	return &mediaRepository{
		db: db,
	}
}

func (mr *mediaRepository) Upload(ctx context.Context, media entities.Media) (entities.Media, error) {
	if err := mr.db.WithContext(ctx).Create(&media).Error; err != nil {
		return entities.Media{}, err
	}

	return media, nil
}

func (mr *mediaRepository) GetMedia(ctx context.Context, mediaId string) (entities.Media, error) {
	var media entities.Media

	err := mr.db.WithContext(ctx).Where("id = ?", mediaId).First(&media).Error

	if err != nil {
		return entities.Media{}, err
	}

	return media, nil
}
