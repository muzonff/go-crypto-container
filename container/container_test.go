package container

import (
	"encoding/json"
	"testing"
)

// TestGenerateRandomBytes checks if the function generates a byte slice of the correct length.
func TestGenerateRandomBytes(t *testing.T) {
	length := 16
	bytes, err := generateRandomBytes(length)

	if err != nil {
		t.Fatalf("Error generating random bytes: %v", err)
	}

	if len(bytes) != length {
		t.Errorf("Expected byte slice of length %d, got %d", length, len(bytes))
	}
}

// TestGenerateRandomNumber checks if the function generates a number greater than or equal to 4096.
func TestGenerateRandomNumber(t *testing.T) {
	randomNumber := generateRandomNumber()

	if randomNumber < 4096 {
		t.Errorf("Expected random number to be greater than or equal to 4096, got %d", randomNumber)
	}
}

// TestCreateContainer checks if the CreateContainer function returns a valid JSON string.
func TestCreateContainer(t *testing.T) {
	plaintext := "hello world"
	password := "password123"

	containerJSON, err := CreateContainer(plaintext, password)
	if err != nil {
		t.Fatalf("Error creating container: %v", err)
	}

	if containerJSON == "" {
		t.Errorf("CreateContainer returned an empty string")
	}

	// Unmarshal to check if it's valid JSON
	var container Container
	err = json.Unmarshal([]byte(containerJSON), &container)
	if err != nil {
		t.Errorf("CreateContainer returned invalid JSON: %v", err)
	}
}

// TestDecryptContainer checks if the DecryptContainer function successfully decrypts the container.
func TestDecryptContainer(t *testing.T) {
	plaintext := "hello world"
	password := "password123"

	containerJSON, err := CreateContainer(plaintext, password)
	if err != nil {
		t.Fatalf("Error creating container: %v", err)
	}

	decryptedText, err := DecryptContainer(containerJSON, password)
	if err != nil {
		t.Fatalf("Error decrypting container: %v", err)
	}

	if decryptedText != plaintext {
		t.Errorf("Expected decrypted text to be '%s', got '%s'", plaintext, decryptedText)
	}
}

// TestDecryptContainerWithWrongPassword checks if the function correctly fails to decrypt with a wrong password.
func TestDecryptContainerWithWrongPassword(t *testing.T) {
	plaintext := "hello world"
	correctPassword := "correctpassword"
	wrongPassword := "wrongpassword"

	containerJSON, err := CreateContainer(plaintext, correctPassword)
	if err != nil {
		t.Fatalf("Error creating container: %v", err)
	}

	_, err = DecryptContainer(containerJSON, wrongPassword)
	if err == nil {
		t.Errorf("DecryptContainer did not return an error with the wrong password")
	} else if err.Error() != "HMAC mismatch" {
		t.Errorf("Expected HMAC mismatch error, got: %v", err)
	}
}

// TestDecodeHex checks if the decodeHex function correctly decodes a valid hex string.
func TestDecodeHex(t *testing.T) {
	hexStr := "48656c6c6f20576f726c64" // "Hello World" in hex
	expected := "Hello World"

	bytes, err := decodeHex(hexStr)
	if err != nil {
		t.Fatalf("Error decoding hex string: %v", err)
	}

	result := string(bytes)

	if result != expected {
		t.Errorf("Expected decoded string to be '%s', got '%s'", expected, result)
	}
}

// TestDecodeHexWithInvalidHex checks if the decodeHex function correctly handles invalid hex strings.
func TestDecodeHexWithInvalidHex(t *testing.T) {
	invalidHexStr := "invalid_hex"

	_, err := decodeHex(invalidHexStr)
	if err == nil {
		t.Errorf("decodeHex did not return an error with invalid hex string")
	}
}

// TestContainerSetters checks if the setters for the Container struct work correctly.
func TestContainerSetters(t *testing.T) {
	container := &Container{}

	// Test SetContainerMeta
	version := "v1.0"
	container.SetContainerMeta(version)
	if container.ContainerMeta.Version != version {
		t.Errorf("Expected ContainerMeta.Version to be '%s', got '%s'", version, container.ContainerMeta.Version)
	}

	// Test SetDeriveInfo
	salt := "someSalt"
	iters := 1000
	container.SetDeriveInfo(salt, iters)
	if container.DeriveInfo.Salt != salt || container.DeriveInfo.Iters != iters {
		t.Errorf("Expected DeriveInfo to be {Salt: '%s', Iters: %d}, got {Salt: '%s', Iters: %d}", salt, iters, container.DeriveInfo.Salt, container.DeriveInfo.Iters)
	}

	// Test SetEncryptionInfo
	iv := "someIV"
	container.SetEncryptionInfo(iv)
	if container.EncryptionInfo.IV != iv {
		t.Errorf("Expected EncryptionInfo.IV to be '%s', got '%s'", iv, container.EncryptionInfo.IV)
	}

	// Test SetContainedData
	encryptedData := "someData"
	hmac := "someHMAC"
	container.SetContainedData(encryptedData, hmac)
	if container.ContainedData.EncryptedData != encryptedData || container.ContainedData.HMAC != hmac {
		t.Errorf("Expected ContainedData to be {EncryptedData: '%s', HMAC: '%s'}, got {EncryptedData: '%s', HMAC: '%s'}", encryptedData, hmac, container.ContainedData.EncryptedData, container.ContainedData.HMAC)
	}
}

// TestCreateContainerRandomness checks if CreateContainer generates different containers for the same input.
func TestCreateContainerRandomness(t *testing.T) {
	plaintext := "same text"
	password := "samepassword"

	container1, err := CreateContainer(plaintext, password)
	if err != nil {
		t.Fatalf("Error creating first container: %v", err)
	}

	container2, err := CreateContainer(plaintext, password)
	if err != nil {
		t.Fatalf("Error creating second container: %v", err)
	}

	if container1 == container2 {
		t.Errorf("CreateContainer should generate different results for the same input due to randomness")
	}
}

// TestHMACVerification checks if HMAC verification correctly identifies tampered data.
func TestHMACVerification(t *testing.T) {
	plaintext := "sensitive information"
	password := "strongpassword"

	// Create a valid container
	containerJSON, err := CreateContainer(plaintext, password)
	if err != nil {
		t.Fatalf("Error creating container: %v", err)
	}

	// Unmarshal to tamper with the data
	var container Container
	if err := json.Unmarshal([]byte(containerJSON), &container); err != nil {
		t.Fatalf("Failed to unmarshal container: %v", err)
	}

	// Tamper with the encrypted data
	tamperedData := container.ContainedData.EncryptedData[:len(container.ContainedData.EncryptedData)-1] + "0"
	container.ContainedData.EncryptedData = tamperedData

	// Marshal the tampered container back to JSON
	tamperedContainerJSON, err := json.Marshal(container)
	if err != nil {
		t.Fatalf("Failed to marshal tampered container: %v", err)
	}

	// Attempt to decrypt the tampered container (should return an error)
	_, err = DecryptContainer(string(tamperedContainerJSON), password)
	if err == nil {
		t.Errorf("DecryptContainer did not return an error with tampered data")
	} else if err.Error() != "HMAC mismatch" {
		t.Errorf("Expected HMAC mismatch error, got: %v", err)
	}
}
