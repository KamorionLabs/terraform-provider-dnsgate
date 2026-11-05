package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSWebIdentityConfig configures sts:GetWebIdentityToken.
type AWSWebIdentityConfig struct {
	Audience         string
	SigningAlgorithm string // RS256 or ES384
	Region           string
	DurationSeconds  int32
}

// STSTokenAPI is the subset of the STS client used, for tests.
type STSTokenAPI interface {
	GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, opts ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// AWSWebIdentityFetch obtains a JWT signed by AWS STS (IAM outbound identity
// federation) for the current AWS principal, from the default credential chain.
func AWSWebIdentityFetch(cfg AWSWebIdentityConfig, newClient func(ctx context.Context) (STSTokenAPI, error)) FetchFunc {
	var (
		once      sync.Once
		client    STSTokenAPI
		clientErr error
	)
	return func(ctx context.Context) (string, time.Time, error) {
		once.Do(func() { client, clientErr = newClient(ctx) })
		if clientErr != nil {
			return "", time.Time{}, clientErr
		}
		in := &sts.GetWebIdentityTokenInput{
			Audience:         []string{cfg.Audience},
			SigningAlgorithm: aws.String(cfg.SigningAlgorithm),
		}
		if cfg.DurationSeconds > 0 {
			in.DurationSeconds = aws.Int32(cfg.DurationSeconds)
		}
		out, err := client.GetWebIdentityToken(ctx, in)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("sts:GetWebIdentityToken: %w", err)
		}
		if out.WebIdentityToken == nil {
			return "", time.Time{}, errors.New("sts:GetWebIdentityToken returned no token")
		}
		var exp time.Time
		if out.Expiration != nil {
			exp = *out.Expiration
		}
		return *out.WebIdentityToken, exp, nil
	}
}

// DefaultSTSClient builds an STS client from the default AWS configuration.
func DefaultSTSClient(region string) func(ctx context.Context) (STSTokenAPI, error) {
	return func(ctx context.Context) (STSTokenAPI, error) {
		var opts []func(*awsconfig.LoadOptions) error
		if region != "" {
			opts = append(opts, awsconfig.WithRegion(region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		return sts.NewFromConfig(cfg), nil
	}
}
