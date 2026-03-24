package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
)

// SMTPEncryption defines the transport-security model for outgoing mail.
type SMTPEncryption string

const (
	// SMTPEncryptionNone — plain TCP, no upgrade (e.g. Mailhog port 1025)
	SMTPEncryptionNone SMTPEncryption = "none"
	// SMTPEncryptionSTARTTLS — plain TCP upgraded to TLS via STARTTLS (port 587)
	SMTPEncryptionSTARTTLS SMTPEncryption = "starttls"
	// SMTPEncryptionTLS — TLS from the first byte, a.k.a. SMTPS (port 465)
	SMTPEncryptionTLS SMTPEncryption = "tls"
)

// SMTPAuthType defines the SMTP authentication mechanism.
type SMTPAuthType string

const (
	SMTPAuthNone    SMTPAuthType = "none"
	SMTPAuthPlain   SMTPAuthType = "plain"
	SMTPAuthLogin   SMTPAuthType = "login"
	SMTPAuthCRAMMD5 SMTPAuthType = "crammd5"
)

// EmailService sends transactional emails via SMTP with configurable
// authentication and transport security.
type EmailService struct {
	host       string
	addr       string
	from       string
	encryption SMTPEncryption
	auth       smtp.Auth
}

func NewEmailService(host, port, from string, authType SMTPAuthType, username, password string, encryption SMTPEncryption) *EmailService {
	return &EmailService{
		host:       host,
		addr:       host + ":" + port,
		from:       from,
		encryption: encryption,
		auth:       buildSMTPAuth(authType, username, password, host),
	}
}

// buildSMTPAuth returns the appropriate smtp.Auth for the requested mechanism.
func buildSMTPAuth(authType SMTPAuthType, username, password, host string) smtp.Auth {
	switch authType {
	case SMTPAuthPlain:
		return smtp.PlainAuth("", username, password, host)
	case SMTPAuthLogin:
		return &loginAuth{username: username, password: password}
	case SMTPAuthCRAMMD5:
		return smtp.CRAMMD5Auth(username, password)
	default:
		return nil
	}
}

// SendDeviceApprovalCode sends the one-time approval code to the user's email.
func (e *EmailService) SendDeviceApprovalCode(to, deviceName, code string) error {
	t, err := template.ParseFiles("./templates/ApprovalCode.html")
	if err != nil {
		return fmt.Errorf("parse email template: %w", err)
	}

	var body bytes.Buffer
	subject := "Validation de votre nouveau device"
	if err := t.Execute(&body, struct {
		DeviceName string
		Code       string
	}{
		DeviceName: deviceName,
		Code:       code,
	}); err != nil {
		return fmt.Errorf("execute email template: %w", err)
	}
	msg := []byte(
		"To: " + to + "\r\n" +
		"From: " + e.from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		body.String(),
	)
	return e.sendMail([]string{to}, msg)
}

// sendMail opens an SMTP connection with the configured encryption/auth and
// delivers msg to to.
func (e *EmailService) sendMail(to []string, msg []byte) error {
	var client *smtp.Client
	var err error

	switch e.encryption {
	case SMTPEncryptionTLS:
		// SMTPS (implicit TLS, typically port 465): wrap TCP in TLS before SMTP.
		tlsCfg := &tls.Config{ServerName: e.host}
		conn, dialErr := tls.Dial("tcp", e.addr, tlsCfg)
		if dialErr != nil {
			return fmt.Errorf("smtp tls dial: %w", dialErr)
		}
		client, err = smtp.NewClient(conn, e.host)
	default:
		// "none" or "starttls": plain TCP first.
		client, err = smtp.Dial(e.addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	defer client.Close() //nolint:errcheck

	if e.encryption == SMTPEncryptionSTARTTLS {
		tlsCfg := &tls.Config{ServerName: e.host}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	if e.auth != nil {
		if err := client.Auth(e.auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(e.from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", addr, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

// loginAuth implements the SMTP LOGIN mechanism, which is not part of the Go
// standard library but is widely supported (e.g. Microsoft 365, many hosters).
type loginAuth struct {
	username string
	password string
}

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch string(fromServer) {
	case "Username:":
		return []byte(a.username), nil
	case "Password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("smtp login: unexpected server challenge %q", string(fromServer))
	}
}
