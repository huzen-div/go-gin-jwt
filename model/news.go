package model

import (
	"golang-jwt/database"

	"gorm.io/gorm"
)

type News struct {
	gorm.Model
	Content string `gorm:"type:text" json:"content"`
	UserID  uint
}

func (news *News) Save() (*News, error) {
	err := database.Database.Create(&news).Error
	if err != nil {
		return &News{}, err
	}
	return news, nil
}
