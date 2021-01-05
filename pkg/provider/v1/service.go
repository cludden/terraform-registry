package v1

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/Jeffail/benthos/v3/lib/util/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	validator "github.com/go-playground/validator/v10"
	"github.com/twitchtv/twirp"
)

const (
	gpgPublicKeyPK = "provider/v1/-/gpg-public-key"
)

// ServiceConfig describes runtime configuration for a Service value
type ServiceConfig struct {
	session.Config `json:",inline" yaml:",inline" mapstructure:",squash"`
	Bucket         string `json:"bucket" validate:"required"`
	Prefix         string `json:"prefix"`
	Table          string `json:"table" validate:"required"`
}

// Service exposes a v1 terraform provider registry service
type Service struct {
	bucket *string
	prefix string
	table  *string

	dynamo   dynamodbiface.DynamoDBAPI
	s3       s3iface.S3API
	validate *validator.Validate
}

// NewService initializes a new registry provider
func NewService(conf ServiceConfig) (*Service, error) {
	v := validator.New()
	if err := v.Struct(conf); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	sess, err := conf.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error initializing s3 session: %v", err)
	}

	svc := &Service{
		bucket: &conf.Bucket,
		prefix: conf.Prefix,
		table:  &conf.Table,

		dynamo:   dynamodb.New(sess),
		s3:       s3.New(sess),
		validate: v,
	}

	_, err = svc.dynamo.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: svc.table,
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.s3.HeadBucket(&s3.HeadBucketInput{
		Bucket: svc.bucket,
	})

	return svc, nil
}

// =============================================================================

// FindProviderPackageInput describes the input to a FindProviderPackage operation
type FindProviderPackageInput struct {
	Provider `json:",inline" validate:"required"`
	Platform `json:",inline" validate:"required"`
	Version  string `json:"version" validate:"required"`
}

// FindProviderPackageOutput describes the output from a successful FindProviderPackage operation
type FindProviderPackageOutput struct {
	Platform            `json:",inline"`
	DownloadURL         string     `json:"download_url"`
	Filename            string     `json:"filename"`
	SHASum              string     `json:"shasum"`
	SHASumsSignatureURL string     `json:"shasums_signature_url"`
	SHASumsURL          string     `json:"shasums_url"`
	SigningKeys         SigningKey `json:"signing_keys"`
	Protocols           []string   `json:"protocols"`
}

// FindProviderPackage provides download url and additional metadata for a particular provider distribution package
func (s *Service) FindProviderPackage(ctx context.Context, input FindProviderPackageInput) (*FindProviderPackageOutput, error) {
	if err := s.validate.Struct(input); err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	// lookup version
	item, err := s.dynamo.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: s.table,
		Key: map[string]*dynamodb.AttributeValue{
			"pk": {
				S: aws.String(versionPK(input.Provider)),
			},
			"sk": {
				S: &input.Version,
			},
		},
	})
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeResourceNotFoundException {
			return nil, twirp.NotFoundError(aerr.Error())
		}
		return nil, err
	}
	if item == nil {
		return nil, twirp.NewError(twirp.NotFound, "")
	}

	// unmarshal version
	var version Version
	if err := dynamodbattribute.UnmarshalMap(item.Item, &version); err != nil {
		return nil, fmt.Errorf("error unmarshalling version: %v", err)
	}

	// validate distribution package exists
	var found bool
	for _, pl := range version.Platforms {
		if pl.Arch == input.Arch && pl.OS == input.OS {
			found = true
			break
		}
	}
	if !found {
		return nil, twirp.NotFoundError("not found")
	}

	// lookup signing key
	var key GPGPublicKey
	keyItem, err := s.dynamo.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: s.table,
		Key: map[string]*dynamodb.AttributeValue{
			"pk": {
				S: aws.String(gpgPublicKeyPK),
			},
			"sk": {
				S: &version.GPGPublicKeyID,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	if keyItem == nil || keyItem.Item == nil {
		return nil, fmt.Errorf("unable to find key with id: %s", version.GPGPublicKeyID)
	}
	if err := dynamodbattribute.UnmarshalMap(keyItem.Item, &key); err != nil {
		return nil, err
	}

	// get checksum file
	filename := fmt.Sprintf("terraform-provider-%s_v%s_%s_%s.zip", strings.ToLower(input.Type), input.Version, input.OS, input.Arch)
	shasumsKey := aws.String(path.Join(s.prefix, input.Namespace, input.Type, input.Version, "checksums.txt"))
	checksums, err := s.s3.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: s.bucket,
		Key:    shasumsKey,
	})
	if err != nil {
		return nil, fmt.Errorf("error downloading shasums: %v", err)
	}
	defer checksums.Body.Close()

	var shasum string
	scanner := bufio.NewScanner(checksums.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if n := len(fields); n != 2 {
			return nil, fmt.Errorf("error parsing shasums: expected line to contain 2 fields, god %d", n)
		}
		if fields[1] == filename {
			shasum = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading shasums: %v", err)
	}
	if shasum == "" {
		return nil, fmt.Errorf("missing shasum for file: %s", filename)
	}

	// generate download url
	downloadReq, _ := s.s3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: s.bucket,
		Key:    aws.String(path.Join(s.prefix, input.Namespace, input.Type, input.Version, filename)),
	})
	downloadURL, err := downloadReq.Presign(time.Minute * 15)
	if err != nil {
		return nil, fmt.Errorf("error generating presigned download url: %v", err)
	}

	// generate shasums url
	shasumsReq, _ := s.s3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: s.bucket,
		Key:    shasumsKey,
	})
	shasumsURL, err := shasumsReq.Presign(time.Minute * 15)
	if err != nil {
		return nil, fmt.Errorf("error generating shasums url: %v", err)
	}

	// generate shasumssignature url
	signatureReq, _ := s.s3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: s.bucket,
		Key:    aws.String(path.Join(s.prefix, input.Namespace, input.Type, input.Version, "checksums.txt.sig")),
	})
	signatureURL, err := signatureReq.Presign(time.Minute * 15)
	if err != nil {
		return nil, fmt.Errorf("error generating signature url: %v", err)
	}

	out := &FindProviderPackageOutput{
		Platform:            input.Platform,
		DownloadURL:         downloadURL,
		Filename:            filename,
		Protocols:           version.Protocols,
		SHASum:              shasum,
		SHASumsSignatureURL: signatureURL,
		SHASumsURL:          shasumsURL,
		SigningKeys: SigningKey{
			GPGPublicKeys: []GPGPublicKey{
				key,
			},
		},
	}

	return out, nil
}

// =============================================================================

// ListAvailableVersionsInput describes the input to a ListAvailableVersions operation
type ListAvailableVersionsInput struct {
	Provider `json:",inline" validate:"required"`
}

// ListAvailableVersionsOutput describes the output from a successful ListAvailableVersions operation
type ListAvailableVersionsOutput struct {
	Versions []Version `json:"versions"`
}

// ListAvailableVersions provides a list of available versions for a particular provider
func (s *Service) ListAvailableVersions(ctx context.Context, input ListAvailableVersionsInput) (*ListAvailableVersionsOutput, error) {
	if err := s.validate.Struct(input); err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	expr, err := expression.NewBuilder().
		WithKeyCondition(expression.Key("pk").Equal(expression.Value(versionPK(input.Provider)))).
		WithProjection(expression.NamesList(
			expression.Name("pk"),
			expression.Name("sk"),
			expression.Name("platforms"),
			expression.Name("protocols"),
			expression.Name("version"),
		)).
		Build()
	if err != nil {
		return nil, fmt.Errorf("error building query expression: %v", err)
	}

	query := &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 s.table,
	}

	versions := []Version{}
	var perr error
	err = s.dynamo.QueryPagesWithContext(ctx, query, func(page *dynamodb.QueryOutput, last bool) bool {
		for _, item := range page.Items {
			var version Version
			if err := dynamodbattribute.UnmarshalMap(item, &version); err != nil {
				perr = fmt.Errorf("error unmarshalling version: %v", err)
				return false
			}
			versions = append(versions, version)
		}
		return !last
	})
	if err != nil {
		return nil, fmt.Errorf("error querying available versions: %v", err)
	}
	if perr != nil {
		return nil, perr
	}

	return &ListAvailableVersionsOutput{
		Versions: versions,
	}, nil
}

// =============================================================================

// PublishVersionInput describes the input to a PublishVersion operation
type PublishVersionInput struct {
	Provider `json:",inline" validate:"required"`
	Version  `json:",inline" validate:"required,dive"`
}

// PublishVersionOutput describes the output from a successful PublishVersion operation
type PublishVersionOutput struct{}

// PublishVersion registers a new provider version
func (s *Service) PublishVersion(ctx context.Context, input PublishVersionInput) (*PublishVersionOutput, error) {
	if err := s.validate.Struct(input); err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	input.Version.PK = versionPK(input.Provider)
	item, err := dynamodbattribute.MarshalMap(input.Version)
	if err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	_, err = s.dynamo.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: s.table,
		Item:      item,
	})
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &PublishVersionOutput{}, nil
}

// =============================================================================

// RegisterGPGPublicKeyInput describes the input to a RegisterGPGPublicKey operation
type RegisterGPGPublicKeyInput struct {
	GPGPublicKey `json:",inline" validate:"required"`
}

// RegisterGPGPublicKeyOutput describes the output from a successful RegisterGPGPublicKey operation
type RegisterGPGPublicKeyOutput struct{}

// RegisterGPGPublicKey registers a new provider version
func (s *Service) RegisterGPGPublicKey(ctx context.Context, input RegisterGPGPublicKeyInput) (*RegisterGPGPublicKeyOutput, error) {
	if err := s.validate.Struct(input); err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	key := input.GPGPublicKey
	key.PK = gpgPublicKeyPK
	item, err := dynamodbattribute.MarshalMap(key)
	if err != nil {
		return nil, twirp.NewError(twirp.Malformed, err.Error())
	}

	_, err = s.dynamo.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: s.table,
		Item:      item,
	})
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &RegisterGPGPublicKeyOutput{}, nil
}

// =============================================================================

// versionPK generates a dynamodb hash key for a provider version
func versionPK(p Provider) string {
	return fmt.Sprintf("provider/version/%s/%s", p.Namespace, p.Type)
}
