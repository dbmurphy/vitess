package iamauthserver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// generateDecryptionKey generates the decryption key using the username and the given timestamp.
func generateDecryptionKey(username, timestamp string) []byte {
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

	for i := 0; i <= 8; i++ {
		timestamp := getUTCTimestampWithOffset(-i * 3600) // Offset by `i` hours
		key := generateDecryptionKey(username, timestamp)

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", "", err
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(encryptedData, encryptedData)

		accessKey, secretKey, embeddedTimestamp, err := unpackDecryptedData(encryptedData)
		if err == nil && isTimestampValid(embeddedTimestamp) {
			return accessKey, secretKey, nil
		}
	}

	return "", "", errors.New("failed to decrypt within the 8-hour validity window")
}

// unpackDecryptedData unpacks the decrypted binary data into access key and secret key.
func unpackDecryptedData(data []byte) (string, string, string, error) {
	buffer := bytes.NewBuffer(data)

	timestampBytes := make([]byte, 8)
	if err := binary.Read(buffer, binary.BigEndian, &timestampBytes); err != nil {
		return "", "", "", err
	}
	timestamp := string(timestampBytes)

	var accessKeyLength uint8
	if err := binary.Read(buffer, binary.BigEndian, &accessKeyLength); err != nil {
		return "", "", "", err
	}
	accessKey := make([]byte, accessKeyLength)
	if err := binary.Read(buffer, binary.BigEndian, &accessKey); err != nil {
		return "", "", "", err
	}

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

// getUTCTimestampWithOffset returns the UTC timestamp (rounded to the nearest hour) with an offset in seconds.
func getUTCTimestampWithOffset(offsetSeconds int) string {
	return time.Now().UTC().Add(time.Duration(offsetSeconds) * time.Second).Format("2006010215")
}

// isTimestampValid checks if the given timestamp is within the acceptable 8-hour window.
func isTimestampValid(timestamp string) bool {
	t, err := time.Parse("2006010215", timestamp)
	if err != nil {
		return false
	}

	now := time.Now().UTC()
	return now.Sub(t) <= 8*time.Hour && now.Sub(t) >= 0
}

// removeMySQLSalt removes the MySQL client-side salt applied to the password.
func removeMySQLSalt(password string) (string, error) {
	passwordBytes, err := hex.DecodeString(password)
	if err != nil {
		return "", err
	}

	if len(passwordBytes) != sha1.Size {
		return "", errors.New("invalid password length")
	}

	return hex.EncodeToString(passwordBytes), nil
}
