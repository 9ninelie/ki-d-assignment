package entity

import (
	"ki-d-assignment/helpers"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type (
	Identity struct {
		Name_AES    string    `json:"name_aes" binding:"required"`
		Name_DES    string    `json:"name_des" binding:"required"`
		Name_RC4    string    `json:"name_rc4" binding:"required"`
		Address_AES string    `json:"address_aes" binding:"required"`
		Address_DES string    `json:"address_des" binding:"required"`
		Address_RC4 string    `json:"address_rc4" binding:"required"`
		CV_ID       uuid.UUID `json:"cv_id"`
		CV_AES      string    `json:"cv_aes" binding:"required"`
		CV_DES      string    `json:"cv_des" binding:"required"`
		CV_RC4      string    `json:"cv_rc4" binding:"required"`
		ID_Card_ID  uuid.UUID `json:"id_card_id"`
		ID_Card_AES string    `json:"id_card_aes" binding:"required"`
		ID_Card_DES string    `json:"id_card_des" binding:"required"`
		ID_Card_RC4 string    `json:"id_card_rc4" binding:"required"`
	}

	Credential struct {
		Username     string `json:"username" binding:"required"`
		Username_AES string `json:"username_aes" binding:"required"`
		Username_DES string `json:"username_des" binding:"required"`
		Username_RC4 string `json:"username_rc4" binding:"required"`
		Password_AES string `json:"password_aes" binding:"required"`
		Password_DES string `json:"password_des" binding:"required"`
		Password_RC4 string `json:"password_rc4" binding:"required"`
	}

	Key struct {
		SecretKey      string `json:"secret" binding:"required"`
		IV             string `json:"iv" binding:"required"`
		SecretKey8Byte string `json:"secret_key_8_byte" binding:"required"`
		IV8Byte        string `json:"iv_8_byte" binding:"required"`
	}
)

type User struct {
	ID uuid.UUID `gorm:"primary_key;not_null;type:char(36)" json:"id"`
	Identity
	Credential
	Key

	Files []Files `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;" binding:"required" json:"files"`
	AllowedUsers []AllowedUser `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;" binding:"required" json:"allowed_users"`

	Timestamp
}

func (User) TableName() string {
	return "users"
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	// Username
	if enc, err := utils.EncryptAES([]byte(u.Username_AES), u.SecretKey, u.IV); err == nil {
		u.Username_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Username_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Username_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Username_RC4), u.SecretKey); err == nil {
		u.Username_RC4 = string(enc)
	}

	// Password
	if enc, err := utils.EncryptAES([]byte(u.Password_AES), u.SecretKey, u.IV); err == nil {
		u.Password_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Password_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Password_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Password_RC4), u.SecretKey); err == nil {
		u.Password_RC4 = string(enc)
	}

	// Identity
	if enc, err := utils.EncryptAES([]byte(u.Name_AES), u.SecretKey, u.IV); err == nil {
		u.Name_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Name_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Name_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Name_RC4), u.SecretKey); err == nil {
		u.Name_RC4 = string(enc)
	}

	if enc, err := utils.EncryptAES([]byte(u.Address_AES), u.SecretKey, u.IV); err == nil {
		u.Address_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Address_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Address_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Address_RC4), u.SecretKey); err == nil {
		u.Address_RC4 = string(enc)
	}

	// CV
	if enc, err := utils.EncryptAES([]byte(u.CV_AES), u.SecretKey, u.IV); err == nil {
		u.CV_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.CV_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.CV_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.CV_RC4), u.SecretKey); err == nil {
		u.CV_RC4 = string(enc)
	}

	// ID_Card
	if enc, err := utils.EncryptAES([]byte(u.ID_Card_AES), u.SecretKey, u.IV); err == nil {
		u.ID_Card_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.ID_Card_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.ID_Card_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.ID_Card_RC4), u.SecretKey); err == nil {
		u.ID_Card_RC4 = string(enc)
	}

	return nil
}

func (u *User) BeforeUpdate(tx *gorm.DB) error {
	// Username
	if enc, err := utils.EncryptAES([]byte(u.Username_AES), u.SecretKey, u.IV); err == nil {
		u.Username_AES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Username_RC4), u.SecretKey); err == nil {
		u.Username_RC4 = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Username_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Username_DES = string(enc)
	}

	// Password
	if enc, err := utils.EncryptAES([]byte(u.Password_AES), u.SecretKey, u.IV); err == nil {
		u.Password_AES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Password_RC4), u.SecretKey); err == nil {
		u.Password_RC4 = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Password_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Password_DES = string(enc)
	}

	// Identity
	if enc, err := utils.EncryptAES([]byte(u.Name_AES), u.SecretKey, u.IV); err == nil {
		u.Name_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Name_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Name_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Name_RC4), u.SecretKey); err == nil {
		u.Name_RC4 = string(enc)
	}

	if enc, err := utils.EncryptAES([]byte(u.Address_AES), u.SecretKey, u.IV); err == nil {
		u.Address_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.Address_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.Address_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.Address_RC4), u.SecretKey); err == nil {
		u.Address_RC4 = string(enc)
	}

	// CV
	if enc, err := utils.EncryptAES([]byte(u.CV_AES), u.SecretKey, u.IV); err == nil {
		u.CV_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.CV_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.CV_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.CV_RC4), u.SecretKey); err == nil {
		u.CV_RC4 = string(enc)
	}

	// ID_Card
	if enc, err := utils.EncryptAES([]byte(u.ID_Card_AES), u.SecretKey, u.IV); err == nil {
		u.ID_Card_AES = string(enc)
	}

	if enc, err := utils.EncryptDES([]byte(u.ID_Card_DES), u.SecretKey8Byte, u.IV8Byte); err == nil {
		u.ID_Card_DES = string(enc)
	}

	if enc, err := utils.EncryptRC4([]byte(u.ID_Card_RC4), u.SecretKey); err == nil {
		u.ID_Card_RC4 = string(enc)
	}

	return nil
}