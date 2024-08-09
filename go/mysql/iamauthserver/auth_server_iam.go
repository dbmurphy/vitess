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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"vitess.io.vitess/go/mysql"
	"vitess.io.vitess/go/mysql/sqlerror"
	"vitess.io.vitess/go/sqltypes"
)

type IAMAuthServer struct{}

// NewIAMAuthServer returns a new instance of IAMAuthServer.
func NewIAMAuthServer() *IAMAuthServer {
	return &IAMAuthServer{}
}

// Authenticate validates the user and password with AWS IAM.
func (server *IAMAuthServer) Authenticate(username, password string, remoteAddr string) (mysql.Getter, error) {
	// Assume `challenge` is obtained from the MySQL server during the handshake process
	var challenge []byte // You need to replace this with the actual challenge used in your server

	// Step 1: Remove MySQL client-side salt
	mysqlSaltedPassword, err := removeMySQLSalt(password, challenge)
	if err != nil {
		return nil, sqlerror.NewSQLError(mysql.ERAccessDeniedError, sqlerror.SQLStateAccessDenied, "Access denied for user '%s'", username)
	}

	// Step 2: Decrypt and extract the access key, secret key, and timestamp from the salted password
	accessKey, secretKey, err := decryptAndExtractKeys(username, mysqlSaltedPassword)
	if err != nil {
		return nil, sqlerror.NewSQLError(mysql.ERAccessDeniedError, sqlerror.SQLStateAccessDenied, "Access denied for user '%s'", username)
	}

	// Step 3: Use the extracted keys to validate with AWS STS
	roleName, err := validateWithSTS(username, accessKey, secretKey)
	if err != nil {
		return nil, sqlerror.NewSQLError(mysql.ERAccessDeniedError, sqlerror.SQLStateAccessDenied, "Access denied for user '%s'", username)
	}

	// Ensure the role name matches the expected username
	if roleName != username {
		return nil, sqlerror.NewSQLError(mysql.ERAccessDeniedError, sqlerror.SQLStateAccessDenied, "Access denied for user '%s'", username)
	}

	// If authentication succeeds, return a simple getter
	return mysql.NewStaticUserGetter(&mysql.StaticUserData{
		Username: username,
		Password: password,
		UserData: &sqltypes.Result{},
	}), nil
}

// decryptAndExtractKeys decrypts the encrypted password using AES-256 and unpacks the binary structure to extract keys.
// It attempts decryption at coarse time intervals within the 8-hour validity window.
func decryptAndExtractKeys(username, encryptedPassword string) (string, string, error) {
	// Convert the encrypted password from hex to bytes
	encryptedData, err := hex.DecodeString(encryptedPassword)
	if err != nil {
		return "", "", err
	}

	// The IV should be the first block size of the encrypted data
	if len(encryptedData) < aes.BlockSize {
		return "", "", errors.New("ciphertext too short")
	}
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	// Attempt decryption at coarse intervals (e.g., every hour) within the past 8 hours
	for i := 0; i <= 8; i++ {
		// Calculate the timestamp for this interval
		timestamp := getUTCTimestampWithOffset(-i * 3600) // Offset by `i` hours

		// Generate the decryption key using the username and this timestamp
		key := generateDecryptionKey(username, timestamp)

		// Create an AES cipher block using the derived key
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", "", err
		}

		// Decrypt the data using CBC mode
		mode := cipher.NewCBCDecrypter(block, iv)
		decryptedData := make([]byte, len(encryptedData))
		mode.CryptBlocks(decryptedData, encryptedData)

		// Attempt to unpack the decrypted data into the access key and secret key
		accessKey, secretKey, embeddedTimestamp, err := unpackDecryptedData(decryptedData)
		if err == nil {
			// Verify that the embedded timestamp is within the 8-hour window
			if isTimestampValid(embeddedTimestamp) {
				return accessKey, secretKey, nil // Successfully decrypted and validated
			}
		}
	}

	return "", "", errors.New("failed to decrypt within the 8-hour validity window")
}

// generateDecryptionKey generates the decryption key using the username and the given timestamp
func generateDecryptionKey(username, timestamp string) []byte {
	// Combine the username (role name) and timestamp, then hash them to create a 32-byte key for AES-256
	keyData := []byte(username + timestamp)
	hash := sha256.Sum256(keyData)
	return hash[:]
}

// getUTCTimestampWithOffset returns the UTC timestamp (rounded to the nearest hour) with an offset in seconds
func getUTCTimestampWithOffset(offsetSeconds int) string {
	return time.Now().UTC().Add(time.Duration(offsetSeconds) * time.Second).Format("2006010215")
}

// unpackDecryptedData unpacks the decrypted binary data into access key, secret key, and timestamp
func unpackDecryptedData(data []byte) (string, string, string, error) {
	// Assuming the format is:
	// [timestamp][accessKeyLength][accessKey][secretKeyLength][secretKey]

	buffer := bytes.NewBuffer(data)

	// Read the timestamp (8 bytes)
	timestampBytes := make([]byte, 8)
	if err := binary.Read(buffer, binary.BigEndian, &timestampBytes); err != nil {
		return "", "", "", err
	}
	embeddedTimestamp := string(timestampBytes)

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

	return string(accessKey), string(secretKey), embeddedTimestamp, nil
}

// isTimestampValid checks if the given timestamp is within the acceptable 8-hour window
func isTimestampValid(timestamp string) bool {
	// Convert the timestamp string to a time.Time object
	t, err := time.Parse("2006010215", timestamp)
	if err != nil {
		return false
	}

	// Check if the timestamp is within the past 8 hours
	now := time.Now().UTC()
	return now.Sub(t) <= 8*time.Hour && now.Sub(t) >= 0
}

// removeMySQLSalt removes the MySQL client-side salt applied to the password
func removeMySQLSalt(password string, challenge []byte) (string, error) {
	passwordBytes, err := hex.DecodeString(password)
	if err != nil {
		return "", err
	}

	if len(passwordBytes) != sha1.Size || len(challenge) != sha1.Size {
		return "", errors.New("invalid password or challenge length")
	}

	sha1Hash := make([]byte, sha1.Size)
	for i := 0; i < sha1.Size; i++ {
		sha1Hash[i] = passwordBytes[i] ^ challenge[i]
	}

	return hex.EncodeToString(sha1Hash), nil
}

// validateWithSTS uses the extracted access key and secret key to authenticate with AWS STS.
func validateWithSTS(roleName, accessKey, secretKey string) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	})
	if err != nil {
		return "", err
	}

	svc := sts.New(sess)

	result, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}

	arn := *result.Arn
	parts := strings.Split(arn, "/")

	if len(parts) < 2 {
		return "", errors.New("invalid role ARN")
	}

	return parts[len(parts)-1], nil
}
