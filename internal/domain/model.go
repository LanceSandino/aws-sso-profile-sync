// Package domain defines the shared, nonsecret CLI and planning contracts.
// Session, assignment, profile and typed outcome models carry no authentication secrets.
package domain

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type Session struct {
	Name     string `json:"name"`
	StartURL string `json:"start_url"`
	Region   string `json:"sso_region"`
}

func (s Session) Normalized() Session { s.StartURL = strings.TrimRight(s.StartURL, "/"); return s }

type Assignment struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	RoleName    string `json:"role_name"`
}
type Profile struct {
	Name       string     `json:"name"`
	Session    Session    `json:"session"`
	Assignment Assignment `json:"assignment"`
	Region     string     `json:"region"`
	Output     string     `json:"output"`
}

func (p Profile) Identity() string {
	s := p.Session.Normalized()
	return s.StartURL + "|" + s.Region + "|" + p.Assignment.AccountID + "|" + p.Assignment.RoleName
}

type Result struct {
	Profile Profile `json:"profile"`
	Status  string  `json:"status"`
	Reason  string  `json:"reason"`
}
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string        { return fmt.Sprintf("%s: %s", e.Code, e.Message) }
func Fail(code, message string) error { return &Error{code, message} }
func ErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed_out"
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "failed"
}
