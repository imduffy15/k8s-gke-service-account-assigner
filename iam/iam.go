package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imduffy15/k8s-gke-service-account-assigner/mappings"
	"github.com/karlseguin/ccache"
	"golang.org/x/oauth2/google"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
)

var accessTokenCache = ccache.New(ccache.Configure())

var idTokenCache = ccache.New(ccache.Configure())

const (
	ttl = time.Minute * 50
)

// Client represents an IAM client.
type Client struct {
}

// Credentials represent an OAuth Access token
type Credentials struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

const (
	tokenType = "Bearer"
)

// ImpersonateServiceAccount returns a service account access token using The IAM Credentials API.
func (iam *Client) ImpersonateServiceAccount(serviceAccountMappingResult *mappings.ServiceAccountMappingResult) (*Credentials, error) {
	serviceAccountMappingResultStr, err := json.Marshal(serviceAccountMappingResult)
	if err != nil {
		return nil, err
	}
	item, err := accessTokenCache.Fetch(string(serviceAccountMappingResultStr), ttl, func() (interface{}, error) {
		ctx := context.Background()

		client, err := google.DefaultClient(ctx, iamcredentials.CloudPlatformScope)
		if err != nil {
			return nil, fmt.Errorf("failed to get google client: %s", err.Error())
		}

		iamCredentialsClient, err := iamcredentials.New(client)
		if err != nil {
			return nil, fmt.Errorf("failed to get iam credentials client: %s", err.Error())
		}

		generateAccessTokenResponse, err := iamCredentialsClient.Projects.ServiceAccounts.GenerateAccessToken(
			fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountMappingResult.ServiceAccount),
			&iamcredentials.GenerateAccessTokenRequest{
				Scope: serviceAccountMappingResult.Scopes,
			},
		).Do()

		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %s", err.Error())
		}

		return generateAccessTokenResponse, nil
	})
	if err != nil {
		return nil, err
	}

	accessToken := item.Value().(*iamcredentials.GenerateAccessTokenResponse)

	expiresTime, err := time.Parse(time.RFC3339, accessToken.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token expiry time %v: %s", accessToken.ExpireTime, err.Error())
	}

	return &Credentials{
		AccessToken: accessToken.AccessToken,
		ExpiresAt:   int(time.Until(expiresTime).Seconds()),
		TokenType:   tokenType,
	}, nil
}

// GenerateIDToken returns a service account id token for for the given audience using The IAM Credentials API.
func (iam *Client) GenerateIDToken(serviceAccountMappingResult *mappings.ServiceAccountMappingResult, audience string) (string, error) {
	serviceAccountMappingResultStr, err := json.Marshal(serviceAccountMappingResult)
	if err != nil {
		return "", err
	}
	item, err := idTokenCache.Fetch(string(serviceAccountMappingResultStr), ttl, func() (interface{}, error) {
		ctx := context.Background()

		client, err := google.DefaultClient(ctx, iamcredentials.CloudPlatformScope)
		if err != nil {
			return nil, err
		}

		iamCredentialsClient, err := iamcredentials.New(client)
		if err != nil {
			return nil, err
		}

		generateIDTokenResponse, err := iamCredentialsClient.Projects.ServiceAccounts.GenerateIdToken(
			fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountMappingResult.ServiceAccount),
			&iamcredentials.GenerateIdTokenRequest{
				Audience: audience,
			},
		).Do()

		if err != nil {
			return nil, err
		}

		return generateIDTokenResponse.Token, nil
	})
	if err != nil {
		return "", err
	}

	return item.Value().(string), nil
}

// NewClient returns a new IAM client.
func NewClient() *Client {
	return &Client{}
}
