package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type AuthType string

const (
	AuthKubeconfig AuthType = "kubeconfig"
	AuthToken      AuthType = "token"
)

type ClusterEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          AuthType `json:"type"`
	APIServer     string   `json:"apiServer,omitempty"`
	Namespace     string   `json:"namespace,omitempty"`
	Insecure      bool     `json:"insecure,omitempty"`
	APIPathPrefix string   `json:"apiPathPrefix,omitempty"`
	Ciphertext    string   `json:"ciphertext"`
	Nonce         string   `json:"nonce"`
}

type ClusterSecret struct {
	KubeconfigContent string `json:"kubeconfigContent,omitempty"`
	Token             string `json:"token,omitempty"`
	CAData            string `json:"caData,omitempty"`
}

type Store struct {
	path string
	key  []byte
}

func New() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".kubetrail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey()
	if err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "clusters.json"), key: key}, nil
}

func (s *Store) List() ([]ClusterEntry, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []ClusterEntry{}, nil
		}
		return nil, err
	}
	var out []ClusterEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) Save(entry ClusterEntry, secret ClusterSecret) (string, error) {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.Name == "" {
		entry.Name = entry.ID[:8]
	}
	plain, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}
	ct, nonce, err := encrypt(s.key, plain)
	if err != nil {
		return "", err
	}
	entry.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	entry.Nonce = base64.StdEncoding.EncodeToString(nonce)
	list, err := s.List()
	if err != nil {
		return "", err
	}
	found := false
	for i, e := range list {
		if e.ID == entry.ID {
			list[i] = entry
			found = true
		}
	}
	if !found {
		list = append(list, entry)
	}
	return entry.ID, s.write(list)
}

func (s *Store) Delete(id string) error {
	list, err := s.List()
	if err != nil {
		return err
	}
	out := list[:0]
	for _, e := range list {
		if e.ID != id {
			out = append(out, e)
		}
	}
	return s.write(out)
}

func (s *Store) Reveal(id string) (ClusterEntry, ClusterSecret, error) {
	list, err := s.List()
	if err != nil {
		return ClusterEntry{}, ClusterSecret{}, err
	}
	for _, e := range list {
		if e.ID != id {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
		if err != nil {
			return e, ClusterSecret{}, fmt.Errorf("decode ct: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
		if err != nil {
			return e, ClusterSecret{}, fmt.Errorf("decode nonce: %w", err)
		}
		plain, err := decrypt(s.key, ct, nonce)
		if err != nil {
			return e, ClusterSecret{}, fmt.Errorf("decrypt: %w", err)
		}
		var sec ClusterSecret
		if err := json.Unmarshal(plain, &sec); err != nil {
			return e, ClusterSecret{}, err
		}
		return e, sec, nil
	}
	return ClusterEntry{}, ClusterSecret{}, fmt.Errorf("cluster %s not found", id)
}

func (s *Store) Path() string { return s.path }

func (s *Store) EncryptValue(plain []byte) (ciphertext, nonce string, err error) {
	ct, n, err := encrypt(s.key, plain)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ct), base64.StdEncoding.EncodeToString(n), nil
}

func (s *Store) DecryptValue(ciphertext, nonce string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	n, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, err
	}
	return decrypt(s.key, ct, n)
}

func (s *Store) write(list []ClusterEntry) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func encrypt(key, plain []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return ct, nonce, nil
}

func decrypt(key, ct, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}
