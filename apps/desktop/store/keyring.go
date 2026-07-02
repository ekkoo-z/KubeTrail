package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keyringService = "kubetrail"
const keyringUser = "master-key"

func LoadOrCreateKey() ([]byte, error) {
	s, err := keyring.Get(keyringService, keyringUser)
	if err == nil && s != "" {
		k, derr := base64.StdEncoding.DecodeString(s)
		if derr != nil {
			return nil, fmt.Errorf("decode stored key: %w", derr)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("stored key has wrong length %d", len(k))
		}
		return k, nil
	}
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("keyring get: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(k)); err != nil {
		return nil, fmt.Errorf("keyring set: %w", err)
	}
	return k, nil
}
