package authz

import "errors"

var (
	ErrCyclicInheritance = errors.New("libauth: cyclic role inheritance")
	ErrInheritanceDepth  = errors.New("libauth: role inheritance too deep")
)