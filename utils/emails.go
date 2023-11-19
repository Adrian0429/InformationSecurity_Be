package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
)

func SimpleSendEmail() {
	var body bytes.Buffer
	template, err := template.ParseFiles("./template.html")
	template.Execute(&body, struct {
		Name string
	}{
		Name: "owner",
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

	msg := "Subject: ini subject " + "\n" + headers + "\n\n" + body.String()

	err = smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"hepmewstorage@gmail.com",
		[]string{"royankaruna@gmail.com"},
		[]byte(msg),
	)

	if err != nil {
		fmt.Println(err)
	}

}
