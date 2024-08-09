package iamauthserver

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

// validateWithSTS uses the extracted access key and secret key to authenticate with AWS STS.
func validateWithSTS(accessKey, secretKey string) (string, error) {
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
	parts := strings.Split(arn, ":")

	// Extract the part of the ARN containing the assumed role information
	roleParts := strings.Split(parts[5], "/")

	// The role name is the second element, following "assumed-role"
	if len(roleParts) < 2 {
		return "", errors.New("invalid role ARN structure")
	}

	return roleParts[1], nil // Extract and return the role name
}
