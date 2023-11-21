package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"

	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/google/uuid"
)

const EMAIL = "http://localhost:8888/api/user/send/"
const DOWN = "http://localhost:888/api/user/getbykey"

func RequestURL(userID uuid.UUID) string {
	return EMAIL + "Request/" + userID.String()
}


func SendRequestEmail(owner dto.UserInfo, requester dto.UserResponse) {
	url := "http://localhost:8888/api/user/send/Acceptance/" + requester.ID
	var body bytes.Buffer
	template, err := template.ParseFiles("utils/template/RequestTemplate.html")
	template.Execute(&body, struct {
		Name      string
		Requester string
		URL       string
	}{
		Name:      owner.Name,
		Requester: requester.Name,
		URL:       url,
	})
	if err != nil {
		fmt.Println("error parsing files")
	}

	auth := smtp.PlainAuth(
		"",
		"hepmewstorage@gmail.com",
		"vlrg zxck ofkl ecmh",
		"smtp.gmail.com",
	)

	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"

	msg := "Subject: File Access Request From : " + requester.Name + "\n" + headers + "\n\n" + body.String()

	err = smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"hepmewstorage@gmail.com",
		[]string{owner.Email},
		[]byte(msg),
	)

	if err != nil {
		fmt.Println(err)
	}

}

func SendAcceptanceEmail(requester dto.UserResponse, keys string, iv string) {
	var body bytes.Buffer
	template, err := template.ParseFiles("utils/template/GrantedTemplate.html")
	template.Execute(&body, struct {
		Name  string
		Symm  string
		InitV string
	}{
		Name:  requester.Name,
		Symm:  keys,
		InitV: iv,
	})

	if err != nil {
		fmt.Println("error parsing files")
	}

	auth := smtp.PlainAuth(
		"",
		"hepmewstorage@gmail.com",
		"vlrg zxck ofkl ecmh",
		"smtp.gmail.com",
	)

	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"

	msg := "Subject: Access Credentials" + "\n" + headers + "\n\n" + body.String()

	err = smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"hepmewstorage@gmail.com",
		[]string{requester.Email},
		[]byte(msg),
	)

	if err != nil {
		fmt.Println(err)
	}

}
