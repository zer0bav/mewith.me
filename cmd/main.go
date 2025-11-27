package main

import (
	"fmt"
	"html/template"
	"log"
	"math"
	"mewith/internal"
	"net/http"
	"os"
	"strings"
	"time"
)

func timeAgo(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)
	minutes := diff.Minutes()
	hours := diff.Hours()
	days := hours / 24
	if minutes < 1 {
		return "Just now"
	}
	if minutes < 60 {
		return fmt.Sprintf("%.0f mins ago", minutes)
	}
	if hours < 24 {
		return fmt.Sprintf("%.0f hours ago", hours)
	}
	if days < 30 {
		return fmt.Sprintf("%.0f days ago", math.Floor(days))
	}
	return t.Format("02 Jan 2006")
}

func main() {
	internal.InitSecurity()
	internal.InitDB()

	var admin internal.User
	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASSWORD")

	if err := internal.DB.Where("username = ?", adminUser).First(&admin).Error; err != nil {
		internal.DB.Create(&internal.User{
			Username: adminUser,
			Password: internal.HashPassword(adminPass),
			IsAdmin:  true,
			About:    "Official Administrator",
		})

	}
	// ------------------------------

	funcMap := template.FuncMap{"timeAgo": timeAgo}
	var err error
	internal.Tmpl, err = template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Template Error: %v", err)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", internal.IndexEndpoint)
	http.HandleFunc("/login", internal.LoginEndpoint)
	http.HandleFunc("/register", internal.RegisterEndpoint)
	http.HandleFunc("/logout", internal.LogoutEndpoint)

	http.HandleFunc("/profile", internal.ProfileEndpoint)
	http.HandleFunc("/profile/update", internal.ProfileUpdateEndpoint)
	http.HandleFunc("/u/", internal.PublicProfileEndpoint)

	http.HandleFunc("/create", internal.CreateTopicEndpoint)
	http.HandleFunc("/topic/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/comment") {
			internal.CommentEndpoint(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/like") {
			internal.LikeEndpoint(w, r)
		} else {
			internal.TopicDetailEndpoint(w, r)
		}
	})

	http.HandleFunc("/my-chats", internal.MyChatsEndpoint)
	http.HandleFunc("/chat/start", internal.StartDirectChatEndpoint)
	http.HandleFunc("/chat/message", internal.SendChatMessageEndpoint)
	http.HandleFunc("/chat/", internal.JoinChatEndpoint)

	http.HandleFunc("/admin", internal.AdminEndpoint)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server running: http://localhost:%s\n", port)
	fmt.Printf("\n--- ADMIN ACCOUNT CREATED ---\nUser: %s\nPass: %s\n-----------------------------\n", adminUser, adminPass)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
