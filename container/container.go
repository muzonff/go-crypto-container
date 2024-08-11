package container

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	mathrnd "math/rand"
	"time"
)

const (
	saltLen = 12
	ivLen   = 16
)

type Container struct {
	ContainerMeta  Meta       `json:"ContainerMeta"`
	DeriveInfo     Derive     `json:"DeriveInfo"`
	EncryptionInfo Encryption `json:"EncryptionInfo"`
	ContainedData  Data       `json:"ContainedData"`
}

type Meta struct {
	Version string `json:"Version"`
}

type Derive struct {
	Salt  string `json:"Salt"`
	Iters int    `json:"Iters"`
}

type Encryption struct {
	IV string `json:"IV"`
}

type Data struct {
	EncryptedData string `json:"EncryptedData"`
	HMAC          string `json:"HMAC"`
}

func (c *Container) SetContainerMeta(version string) {
	c.ContainerMeta = Meta{Version: version}
}

func (c *Container) SetDeriveInfo(salt string, iters int) {
	c.DeriveInfo = Derive{Salt: salt, Iters: iters}
}

func (c *Container) SetEncryptionInfo(iv string) {
	c.EncryptionInfo = Encryption{IV: iv}
}

func (c *Container) SetContainedData(encryptedData, hmac string) {
	c.ContainedData = Data{EncryptedData: encryptedData, HMAC: hmac}
}

func generateRandomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func generateRandomNumber() int {
	iterations := 130000
	elapsed := workload(iterations)
	source := mathrnd.NewSource(time.Now().UnixNano() + elapsed)
	random := mathrnd.New(source)
	randomNumber := random.Intn(int(elapsed) + 1)
	if randomNumber < 4096 {
		return 4096
	}
	return randomNumber
}

func workload(iterations int) int64 {
	start := time.Now()
	var sum int64 = 1
	for i := 0; i < iterations; i++ {
		sum *= 2
	}
	elapsed := time.Since(start).Nanoseconds()
	return elapsed
}

func CreateContainer(plaintext, password string) (string, error) {
	hmac := sha256.Sum256([]byte(plaintext))
	salt, err := generateRandomBytes(saltLen)
	if err != nil {
		return "", err
	}
	iterCount := generateRandomNumber()
	iv, err := generateRandomBytes(ivLen)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), salt, iterCount, 32, sha256.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	container := &Container{}
	container.SetContainerMeta("v1.0")
	container.SetDeriveInfo(hex.EncodeToString(salt), iterCount)
	container.SetEncryptionInfo(hex.EncodeToString(iv))
	container.SetContainedData(hex.EncodeToString(ciphertext), hex.EncodeToString(hmac[:]))

	b, err := json.Marshal(container)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func DecryptContainer(containerJSON, password string) (string, error) {
	var container Container
	err := json.Unmarshal([]byte(containerJSON), &container)
	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(container.DeriveInfo.Salt)
	if err != nil {
		return "", err
	}
	encrypted, err := hex.DecodeString(container.ContainedData.EncryptedData)
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(container.EncryptionInfo.IV)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), salt, container.DeriveInfo.Iters, 32, sha256.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(encrypted)-aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, encrypted[aes.BlockSize:])

	check := sha256.Sum256(plaintext)
	if hex.EncodeToString(check[:]) != container.ContainedData.HMAC {
		return "", errors.New("HMAC mismatch")
	}

	return string(plaintext), nil
}

func decodeHex(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
