package store

import "errors"

var (
	ErrUserNotFound = errors.New("libauth: user not found")
	ErrRoleNotFound = errors.New("libauth: role not found")
	ErrUserExists   = errors.New("libauth: user already exists")
	ErrRoleExists   = errors.New("libauth: role already exists")
	ErrEmptyName    = errors.New("libauth: empty name")
)