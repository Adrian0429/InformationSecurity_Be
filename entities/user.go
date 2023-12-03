package entities

import (
	"github.com/Caknoooo/golang-clean_template/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type (
	User struct {
		ID           uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
		Name         string    `json:"name"`
		Email        string    `json:"email"`
		Password     string    `json:"password"`
		Role         string    `json:"role"`
		SymmetricKey string    `json:"symmetric_key"`
		PublicKey    string    `json:"public_key"`
		PrivateKey   string    `json:"private_key"`
		IV           string    `json:"iv"`
		KTP          string    `json:"ktp_path,omitempty"`
		Media        []Media   `json:"media"`
		Timestamp
	}

	Media struct {
		ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
		Filename  string    `json:"filename"`
		Path      string    `json:"path"`
		Request   string    `json:"request_url"`
		DownKey   string    `json:"downkey"`
		Signature []byte    `json:"signature"`
		Signed    bool      `json:"signed"`

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
