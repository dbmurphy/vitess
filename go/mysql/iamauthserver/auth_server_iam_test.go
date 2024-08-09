package iamauthserver

import (
	"crypto/aes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Mock data for testing
const (
	testRoleName  = "test-role"
	testAccessKey = "AKIAEXAMPLE"
	testSecretKey = "exampleSecretKey12345678901234567890"
	testTimestamp = "2024010101" // An example timestamp
)

func TestGenerateDecryptionKey(t *testing.T) {
	key := generateDecryptionKey(testRoleName, testTimestamp)
	require.NotNil(t, key, "Decryption key should not be nil")
	require.Equal(t, 32, len(key), "Decryption key should be 32 bytes long")
}

func TestDecryptAndExtractKeys(t *testing.T) {
	// This will involve encrypting some test data and then attempting to decrypt it
	saltedPassword, iv := encryptTestPassword(testRoleName, testAccessKey, testSecretKey, testTimestamp)
	combinedPassword := iv + saltedPassword

	accessKey, secretKey, err := decryptAndExtractKeys(testRoleName, combinedPassword)
	require.NoError(t, err, "Decryption should not produce an error")
	assert.Equal(t, testAccessKey, accessKey, "Access key should match")
	assert.Equal(t, testSecretKey, secretKey, "Secret key should match")
}

func TestIsTimestampValid(t *testing.T) {
	timestamp := time.Now().UTC().Format("2006010215")
	assert.True(t, isTimestampValid(timestamp), "Timestamp should be valid within 8-hour window")

	oldTimestamp := time.Now().Add(-9 * time.Hour).UTC().Format("2006010215")
	assert.False(t, isTimestampValid(oldTimestamp), "Timestamp should be invalid outside 8-hour window")
}

func TestAuthenticate(t *testing.T) {
	// Mock server and a salted password
	server := NewIAMAuthServer()
	saltedPassword, iv := encryptTestPassword(testRoleName, testAccessKey, testSecretKey, testTimestamp)
	combinedPassword := iv + saltedPassword

	getter, err := server.Authenticate(testRoleName, combinedPassword, "127.0.0.1")
	require.NoError(t, err, "Authentication should succeed")
	require.NotNil(t, getter, "Getter should not be nil")

	userData := getter.GetUserData()
	assert.Equal(t, testRoleName, userData.Username, "Username should match")
}

// Helper function to encrypt test data
func encryptTestPassword(roleName, accessKey, secretKey, timestamp string) (string, string) {
	// Generate the encryption key
	key := generateDecryptionKey(roleName, timestamp)

	// Combine the test data into a binary format
	binaryData := timestamp + string(byte(len(accessKey))) + accessKey + string(byte(len(secretKey))) + secretKey

	// Encrypt the data
	cipher, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(cipher, iv)
	encrypted := make([]byte, len(binaryData))
	mode.CryptBlocks(encrypted, []byte(binaryData))

	// Return the IV and the encrypted data as hex strings
	return hex.EncodeToString(encrypted), hex.EncodeToString(iv)
}
