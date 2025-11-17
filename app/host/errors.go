package main

import "errors"

var (
	ErrAborted         = errors.New("aborted")
	ErrDeviceHasNoKeys = errors.New("device has no keys. Run `tezsign-host init` then `tezsign-host new` first")
	ErrEmptyPassphrase = errors.New("empty passphrase")
	ErrNoKeysSelected  = errors.New("no keys selected")
)
