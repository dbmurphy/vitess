package iamauthserver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// generateDecryptionKey generates the decryption key using the username and the given timestamp
func generateDecryptionKey(username, timestamp string) []byte {
	// Combine the username (role name) and timestamp, then hash them to create a 32-byte key for AES-256
	keyData := []byte(username + timestamp)
	hash := sha256.Sum256(keyData)
	return hash[:]
}

// decryptAndExtractKeys decrypts the encrypted password using AES-256 and unpacks the binary structure to extract keys.
func decryptAndExtractKeys(username, encryptedPassword string) (string, string, error) {
	encryptedData, err := hex.DecodeString(encryptedPassword)
	if err != nil {
		return "", "", err
	}

	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	timestamp := getUTCTimestampWithOffset(0) // Use current timestamp
	key := generateDecryptionKey(username, timestamp)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)

	return unpackDecryptedData(encryptedData)
}

// unpackDecryptedData unpacks the decrypted binary data into access key and secret key
func unpackDecryptedData(data []byte) (string, string, string, error) {
	buffer := bytes.NewBuffer(data)

	// Extract the timestamp
	timestampBytes := make([]byte, 8)
	if err := binary.Read(buffer, binary.BigEndian, &timestampBytes); err != nil {
		return "", "", "", err
	}
	timestamp := string(timestampBytes)

	// Extract the access key
	var accessKeyLength uint8
	if err := binary.Read(buffer, binary.BigEndian, &accessKeyLength); err != nil {
		return "", "", "", err
	}
	accessKey := make([]byte, accessKeyLength)
	if err := binary.Read(buffer, binary.BigEndian, &accessKey); err != nil {
		return "", "", "", err
	}

	// Extract the secret key
	var secretKeyLength uint8
	if err := binary.Read(buffer, binary.BigEndian, &secretKeyLength); err != nil {
		return "", "", "", err
	}
	secretKey := make([]byte, secretKeyLength)
	if err := binary.Read(buffer, binary.BigEndian, &secretKey); err != nil {
		return "", "", "", err
	}

	return string(accessKey), string(secretKey), timestamp, nil
}
