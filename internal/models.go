package internal

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
	IsAdmin  bool   `gorm:"default:false"`
	About    string
}

type Topic struct {
	ID        string `gorm:"primaryKey"`
	Title     string `gorm:"not null"`
	Content   string `gorm:"not null"`
	Author    string
	Likes     int       `gorm:"default:0"`
	Comments  []Comment `gorm:"foreignKey:TopicID;constraint:OnDelete:CASCADE;"`
	CreatedAt time.Time
}

type Comment struct {
	ID        string `gorm:"primaryKey"`
	Content   string `gorm:"not null"`
	Author    string
	TopicID   string
	CreatedAt time.Time
}

// Beğeni Takibi
type Vote struct {
	ID      uint   `gorm:"primaryKey"`
	UserID  uint   `gorm:"not null"`
	TopicID string `gorm:"not null"`
}

// Chat Odası
type ChatRoom struct {
	ID         string `gorm:"primaryKey"`
	Password   string `gorm:"not null"`
	Creator    string
	TargetUser string
	CreatedAt  time.Time
	Messages   []ChatMessage `gorm:"foreignKey:RoomID;constraint:OnDelete:CASCADE;"`
}

type ChatMessage struct {
	ID        uint `gorm:"primaryKey"`
	RoomID    string
	Author    string
	Content   string
	CreatedAt time.Time
}
