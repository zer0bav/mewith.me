package internal

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
)

var DB *gorm.DB

func InitDB() {
	var err error
	DB, err = gorm.Open(sqlite.Open("data/anonforum.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Veritabanı hatası:", err)
	}

	// Tabloları otomatik oluştur
	err = DB.AutoMigrate(&User{}, &Topic{}, &Comment{}, &Vote{}, &ChatRoom{}, &ChatMessage{})
	if err != nil {
		log.Fatal("Migration hatası:", err)
	}
}
