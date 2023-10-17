package entities

import (
	"github.com/Caknoooo/golang-clean_template/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type (
	User struct {
		ID       uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
		Name     string    `json:"name"`
		Email    string    `json:"email"`
		Password string    `json:"password"`
		Role     string    `json:"role"`
		Key      string    `json:"key"`
		IV       string    `json:"iv"`
		KTP      string   `json:"ktp_path,omitempty"`
		Media    []Media   `json:"media"`
		Timestamp
	}

	Media struct {
		ID       uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
		Filename string    `json:"filename"`
		Path     string    `json:"path"`

		UserID uuid.UUID `gorm:"type:uuid" json:"-"`
		User   User      `gorm:"foreignKey:UserID" json:"-"`
	}
)

func (u *User) BeforeCreate(tx *gorm.DB) error {
	var err error
	u.Password, err = helpers.HashPassword(u.Password)
	if err != nil {
		return err
	}
	return nil
}
