package idkey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

// Data 密文编码结构
type Data struct {
	EncodeOptions        // 加密选项
	Hash          []byte // 密码密文
	Salt          []byte // 加密盐值
}

// EncodeOptions 密文编码选项
type EncodeOptions struct {
	Time    uint32 // 时间参数
	Memory  uint32 // 内存参数
	Threads uint8  // 线程参数
	KeyLen  uint32 // 密文长度
}

// Encode 将密码编码成密文
func Encode(password []byte, options *EncodeOptions) string {
	salt := generateSalt(16)
	data := &Data{
		Hash: nil,
		Salt: salt,
	}
	if options != nil {
		data.EncodeOptions = *options
	} else {
		data.EncodeOptions = EncodeOptions{
			Time:    1,
			Memory:  64 * 1024,
			Threads: 4,
			KeyLen:  32,
		}
	}
	hash := argon2.IDKey(
		password,
		data.Salt,
		data.Time,
		data.Memory,
		data.Threads,
		data.KeyLen,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		data.Memory,
		data.Time,
		data.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// Decode 获取密文编码结构
func Decode(passwordHash string) (data *Data, err error) {
	data = &Data{}
	params := strings.Split(passwordHash, "$")
	if len(params) != 6 {
		err = errors.New("input error")
		return
	}
	var version int
	_, err = fmt.Sscanf(
		params[2],
		"v=%d",
		&version,
	)
	if err != nil {
		return
	}
	if version != argon2.Version {
		err = errors.New("not support")
		return
	}
	_, err = fmt.Sscanf(
		params[3],
		"m=%d,t=%d,p=%d",
		&data.Memory,
		&data.Time,
		&data.Threads,
	)
	if err != nil {
		return
	}
	salt, err := base64.RawStdEncoding.DecodeString(params[4])
	if err != nil {
		return
	}
	data.Salt = salt
	hash, err := base64.RawStdEncoding.DecodeString(params[5])
	if err != nil {
		return
	}
	data.Hash = hash
	data.KeyLen = uint32(len(hash))
	return
}

// Verify 验证密码编码后是否等于密文
func Verify(password []byte, passwordHash string) bool {
	data, err := Decode(passwordHash)
	if err != nil {
		return false
	}
	hash := argon2.IDKey(
		password,
		data.Salt,
		data.Time,
		data.Memory,
		data.Threads,
		data.KeyLen,
	)
	return bytes.Equal(hash, data.Hash)
}

func generateSalt(l int) (b []byte) {
	b = make([]byte, l)
	_, _ = rand.Read(b)
	return
}
