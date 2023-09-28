package repository

import (
	"context"

	"github.com/Caknoooo/golang-clean_template/entities"
	"gorm.io/gorm"
)

type MediaRepository interface {
	Upload(ctx context.Context, media entities.Media) (entities.Media, error)
	GetMedia(ctx context.Context, mediaId string) (entities.Media, error)
}

type mediaRepository struct {
	db *gorm.DB
}

func NewMediaRepository(db *gorm.DB) MediaRepository {
	return &mediaRepository{
		db: db,
	}
}

func (r *mediaRepository) Upload(ctx context.Context, media entities.Media) (entities.Media, error) {
	if err := r.db.WithContext(ctx).Create(&media).Error; err != nil {
		return entities.Media{}, err
	}

	return media, nil
}

func (r *mediaRepository) GetMedia(ctx context.Context, mediaId string) (entities.Media, error) {
	var media entities.Media

	err := r.db.WithContext(ctx).Where("id = ?", mediaId).First(&media).Error

	if err != nil {
		return entities.Media{}, err
	}

	return media, nil
}
