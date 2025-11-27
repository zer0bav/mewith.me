package internal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

var Tmpl *template.Template

func GenerateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s", s[0:4], s[4:8], s[8:12], s[12:16])
}

// --- FORUM İŞLEMLERİ ---

func IndexEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	user, isLoggedIn := GetUserFromRequest(r)

	var topics []Topic

	// Arama ve Sıralama
	query := r.URL.Query().Get("q")
	dbCtx := DB.Preload("Comments").Order("likes desc")

	if query != "" {
		dbCtx = dbCtx.Where("title LIKE ?", "%"+query+"%")
	}

	dbCtx.Find(&topics)

	Tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Title": "Feed", "User": user, "LoggedIn": isLoggedIn, "Topics": topics, "Query": query,
	})
}

func CreateTopicEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}
	// Başlık ve içerik boşluk kontrolü
	title := strings.TrimSpace(r.FormValue("title"))
	content := strings.TrimSpace(r.FormValue("content"))

	if title == "" || content == "" {
		http.Redirect(w, r, "/", 303) // Veya hata mesajı gösterilebilir
		return
	}

	DB.Create(&Topic{
		ID: GenerateID(), Title: title, Content: content,
		Author: user.Username, CreatedAt: time.Now(),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func TopicDetailEndpoint(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/topic/")
	user, isLoggedIn := GetUserFromRequest(r)

	var topic Topic
	if err := DB.Preload("Comments").First(&topic, "id = ?", id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	Tmpl.ExecuteTemplate(w, "topic.html", map[string]interface{}{
		"Title": topic.Title, "Topic": topic, "User": user, "LoggedIn": isLoggedIn,
	})
}

func CommentEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	topicID := parts[2]

	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		http.Redirect(w, r, "/topic/"+topicID, 303)
		return
	}

	DB.Create(&Comment{
		ID: GenerateID(), Content: content, Author: user.Username,
		TopicID: topicID, CreatedAt: time.Now(),
	})
	http.Redirect(w, r, "/topic/"+topicID, http.StatusSeeOther)
}

func LikeEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	topicID := parts[2]

	var existingVote Vote
	result := DB.Where("user_id = ? AND topic_id = ?", user.ID, topicID).First(&existingVote)

	if result.Error == nil {
		DB.Delete(&existingVote)
		DB.Model(&Topic{}).Where("id = ?", topicID).UpdateColumn("likes", gorm.Expr("likes - ?", 1))
	} else {
		newVote := Vote{UserID: user.ID, TopicID: topicID}
		DB.Create(&newVote)
		DB.Model(&Topic{}).Where("id = ?", topicID).UpdateColumn("likes", gorm.Expr("likes + ?", 1))
	}

	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// --- ADMIN ---

func AdminEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "Forbidden: Admin Access Only", 403)
		return
	}

	if r.Method == "POST" {
		topicID := r.FormValue("delete_id")
		DB.Delete(&Topic{}, "id = ?", topicID)
	}

	var allTopics []Topic
	DB.Order("created_at desc").Find(&allTopics)
	Tmpl.ExecuteTemplate(w, "admin.html", map[string]interface{}{"Title": "Admin Panel", "User": user, "Topics": allTopics})
}

// --- AUTH (GÜNCELLENDİ: BOŞLUK KONTROLÜ) ---

func LoginEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		Tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}
	// POST
	u := strings.TrimSpace(r.FormValue("username"))
	p := strings.TrimSpace(r.FormValue("password"))

	// Boşluk kontrolü
	if u == "" || p == "" {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Username and password cannot be empty!"})
		return
	}

	var user User
	if err := DB.Where("username = ?", u).First(&user).Error; err != nil {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Invalid user or password!"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(user.Password), []byte(HashPassword(p))) != 1 {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Invalid user or password!"})
		return
	}
	token, _ := CreateJWT(user.Username, user.IsAdmin)
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true, Path: "/", Expires: time.Now().Add(24 * time.Hour)})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RegisterEndpoint(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.FormValue("username"))
	p := strings.TrimSpace(r.FormValue("password"))

	// Boşluk kontrolü
	if u == "" || p == "" {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Username and password cannot be empty!"})
		return
	}
	if len(p) < 6 {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Password must be at least 6 characters long!"})
		return
	}

	if err := DB.Where("username = ?", u).First(&User{}).Error; err == nil {
		Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Username taken!"})
		return
	}
	DB.Create(&User{Username: u, Password: HashPassword(p)})
	Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Success": "Registration successful! Please login."})
}

func LogoutEndpoint(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "auth_token", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- CHAT & PROFIL ---

func ProfileEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}

	DB.First(&user, user.ID)

	var myTopics []Topic
	DB.Where("author = ?", user.Username).Order("created_at desc").Find(&myTopics)

	Tmpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
		"Title": "Profil", "User": user, "LoggedIn": true, "UserTopics": myTopics,
	})
}

func PublicProfileEndpoint(w http.ResponseWriter, r *http.Request) {
	targetUsername := strings.TrimPrefix(r.URL.Path, "/u/")
	me, isLoggedIn := GetUserFromRequest(r)

	var targetUser User
	if err := DB.Where("username = ?", targetUsername).First(&targetUser).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	var userTopics []Topic
	DB.Where("author = ?", targetUser.Username).Order("created_at desc").Find(&userTopics)

	Tmpl.ExecuteTemplate(w, "public_profile.html", map[string]interface{}{
		"Title": targetUser.Username, "TargetUser": targetUser, "User": me, "LoggedIn": isLoggedIn, "UserTopics": userTopics,
	})
}

func ProfileUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return
	}

	user.About = r.FormValue("about")
	DB.Model(&user).Update("about", user.About)

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func StartDirectChatEndpoint(w http.ResponseWriter, r *http.Request) {
	me, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}

	targetUser := r.FormValue("target_user")
	if targetUser == "" || targetUser == me.Username {
		http.Redirect(w, r, "/profile", 303)
		return
	}

	var room ChatRoom
	err := DB.Where("(creator = ? AND target_user = ?) OR (creator = ? AND target_user = ?)",
		me.Username, targetUser, targetUser, me.Username).First(&room).Error

	if err == nil {
		http.Redirect(w, r, fmt.Sprintf("/chat/%s?pwd=%s", room.ID, room.Password), http.StatusSeeOther)
		return
	}

	newRoom := ChatRoom{
		ID:         GenerateID(),
		Password:   GenerateID()[0:12],
		Creator:    me.Username,
		TargetUser: targetUser,
		CreatedAt:  time.Now(),
	}
	DB.Create(&newRoom)
	http.Redirect(w, r, fmt.Sprintf("/chat/%s?pwd=%s", newRoom.ID, newRoom.Password), http.StatusSeeOther)
}

func MyChatsEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}

	var rooms []ChatRoom
	DB.Where("creator = ? OR target_user = ?", user.Username, user.Username).Order("created_at desc").Find(&rooms)

	Tmpl.ExecuteTemplate(w, "my_chats.html", map[string]interface{}{
		"Title": "Mesajlarım", "User": user, "LoggedIn": true, "Rooms": rooms,
	})
}

func JoinChatEndpoint(w http.ResponseWriter, r *http.Request) {
	roomID := strings.TrimPrefix(r.URL.Path, "/chat/")
	if strings.Contains(roomID, "?") {
		roomID = strings.Split(roomID, "?")[0]
	}

	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", 303)
		return
	}

	var room ChatRoom
	if err := DB.Preload("Messages").First(&room, "id = ?", roomID).Error; err != nil {
		http.Error(w, "Chat odası bulunamadı", 404)
		return
	}

	inputPwd := r.FormValue("password")
	queryPwd := r.URL.Query().Get("pwd")
	isParticipant := (user.Username == room.Creator || user.Username == room.TargetUser)

	if isParticipant && queryPwd == "" {
		queryPwd = room.Password
	}

	if inputPwd == "" && queryPwd == "" {
		Tmpl.ExecuteTemplate(w, "chat.html", map[string]interface{}{
			"Title": "Giriş", "RoomID": roomID, "AskPassword": true, "User": user, "LoggedIn": true,
		})
		return
	}

	checkPwd := inputPwd
	if checkPwd == "" {
		checkPwd = queryPwd
	}

	if room.Password != checkPwd {
		Tmpl.ExecuteTemplate(w, "chat.html", map[string]interface{}{
			"Title": "Hata", "RoomID": roomID, "AskPassword": true, "Error": "Yanlış Parola!", "User": user, "LoggedIn": true,
		})
		return
	}

	Tmpl.ExecuteTemplate(w, "chat.html", map[string]interface{}{
		"Title": "Sohbet", "Room": room, "User": user, "LoggedIn": true, "CurrentPassword": checkPwd,
	})
}

func SendChatMessageEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return
	}

	roomID := r.FormValue("room_id")
	content := r.FormValue("content")
	currentPwd := r.FormValue("password")

	DB.Create(&ChatMessage{
		RoomID: roomID, Author: user.Username, Content: content, CreatedAt: time.Now(),
	})

	http.Redirect(w, r, fmt.Sprintf("/chat/%s?pwd=%s", roomID, currentPwd), http.StatusSeeOther)
}
