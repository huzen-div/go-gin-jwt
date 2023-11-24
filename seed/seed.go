package seed

import (
	"fmt"
	"golang-jwt/model"

	"gorm.io/gorm"
)

var users = []model.User{
	{
		Username: "Kelvin",
		Password: "Kelvin163",
	},
}

func Load(db *gorm.DB) {
	var user model.User
	err := db.Where("username=?", users[0].Username).Find(&user).Error
	if err != nil {
		fmt.Println("Duplicate key in username.")
	} else {
		if len(user.Username) < 1 {
			db.Create(&users)
			fmt.Println("Successfully seed to the database")
		}
	}
}
