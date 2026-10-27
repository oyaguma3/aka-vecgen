// Package kek は、加入者の鍵（Ki・OPc）とサーバー証明書の秘密鍵を暗号化する鍵（KEK）を扱う（設計概要 §8）。
// radsec-ca の internal/kek にそろえている。
//
// KEK は 32 バイトの乱数で、ファイル（Docker の secrets）で渡す。ファイルには 16 進の 64 文字で書く（前後の空白は無視する）。
// 暗号化は AES-256-GCM で、nonce は 12 バイトの乱数。暗号文は nonce ‖ 暗号文 の 1 つのバイト列にする。
// AAD には行の識別（例 aka-vecgen/sub/<IMSI>）を入れ、暗号文を別の行に移しても復号できないようにする。
// Valkey には KEK の識別子（SHA-256 の先頭 8 バイトの 16 進）だけを持つ。
package kek

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// Size は KEK の長さ（バイト）。
const Size = 32

// ErrDecrypt は復号できなかったこと（KEK が違う、別の行の暗号文、壊れている）を表す。
var ErrDecrypt = errors.New("kek: cannot decrypt (wrong KEK, or the ciphertext belongs to another record)")

// KEK は暗号化の鍵。
type KEK struct {
	aead cipher.AEAD
	id   string
}

// ID は KEK の識別子。
func (k *KEK) ID() string { return k.id }

// New は 32 バイトの鍵から KEK を作る。
func New(key []byte) (*KEK, error) {
	if len(key) != Size {
		return nil, fmt.Errorf("kek: the key must be %d bytes (got %d)", Size, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	return &KEK{aead: aead, id: hex.EncodeToString(sum[:8])}, nil
}

// Load は KEK のファイルを読む。
func Load(path string) (*KEK, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kek: read %s: %w", path, err)
	}
	key, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(key) != Size {
		return nil, fmt.Errorf("kek: %s must contain %d random bytes in hexadecimal (%d characters). Create one with aka-vecgen gen-kek", path, Size, Size*2)
	}
	return New(key)
}

// Generate は新しい KEK を作り、16 進で w に書く。
func Generate(w io.Writer) (*KEK, error) {
	key := make([]byte, Size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(w, hex.EncodeToString(key)); err != nil {
		return nil, err
	}
	return New(key)
}

// GenerateFile は新しい KEK のファイルを作る（16 進、権限 0600）。ファイルがあれば上書きしない。
func GenerateFile(path string) (*KEK, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("kek: %s already exists (it is not overwritten)", path)
	}
	if err != nil {
		return nil, err
	}
	k, err := Generate(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return k, nil
}

// Seal は plain を暗号化し、nonce ‖ 暗号文 を返す。
func (k *KEK) Seal(plain []byte, aad string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plain)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

// Open は nonce ‖ 暗号文 を復号する。KEK・aad のどれかが違えば ErrDecrypt を返す。
func (k *KEK) Open(sealed []byte, aad string) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n+k.aead.Overhead() {
		return nil, ErrDecrypt
	}
	p, err := k.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return p, nil
}
