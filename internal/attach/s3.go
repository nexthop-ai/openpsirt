package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Bucket keeps bytes in an object store reached over the S3 API, which is what
// MinIO, Ceph and every cloud provider speak.
type Bucket struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}

// NewBucket returns a store, or nil where the deployment configured none .
//
// **Credentials are taken from the environment when none are configured**,
// which is the whole reason for the official client: a deployment on
// a cloud provider gets a role that rotates rather than a long-lived key
// somebody had to put in a variable and then keep.
//
// An endpoint is what a self-hosted store needs and what a cloud one does not,
// so it is optional; path style goes with it, because a self-hosted store is
// usually addressed that way and a provider usually is not.
func NewBucket(ctx context.Context, endpoint, bucket, region, key, secret, token string,
	pathStyle bool) (*Bucket, error) {

	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return nil, nil
	}
	options := []func(*awsconfig.LoadOptions) error{}
	if region = strings.TrimSpace(region); region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}
	// Configured credentials win over whatever the environment offers. An
	// operator who names a key means that key, and silently preferring an
	// instance role would be the tool deciding who it is.
	if key != "" && secret != "" {
		options = append(options, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(key, secret, token)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("object store credentials: %w", err)
	}
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("object store endpoint: %w", err)
		}
		// Plain HTTP is refused except to this machine. A presigned URL is a
		// bearer token in an address, and one crossing a network in the clear
		// is a file anybody on the path may fetch — the redirect is the part
		// that leaves us, so the rule belongs here rather than in a document.
		if parsed.Scheme != "https" && !loopback(parsed.Hostname()) {
			return nil, fmt.Errorf(
				"object store endpoint must be https, or loopback for development: %s", endpoint)
		}
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = pathStyle
	})
	return &Bucket{client: client, presign: s3.NewPresignClient(client), bucket: bucket}, nil
}

func loopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (b *Bucket) Name() string { return "s3" }

func (b *Bucket) Put(ctx context.Context, key string, body io.Reader, size int64,
	contentType string) error {

	// Streamed rather than held. The signature covers the envelope and TLS
	// covers the bytes, which is what lets a reader be passed through instead
	// of a slice the size of the file.
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("store object: %w", err)
	}
	return nil
}

func (b *Bucket) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket), Key: aws.String(key),
	})
	if err != nil {
		var missing *types.NoSuchKey
		if errors.As(err, &missing) {
			return nil, ErrNoSuchObject
		}
		return nil, fmt.Errorf("read object: %w", err)
	}
	return out.Body, nil
}

func (b *Bucket) Delete(ctx context.Context, key string) error {
	// Removing what is already gone answers successfully on S3, which is the
	// outcome a redaction asked for.
	_, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.bucket), Key: aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("remove object: %w", err)
	}
	return nil
}

// URLFor signs a short-lived address, with the headers we chose overriding
// whatever was stored.
func (b *Bucket) URLFor(ctx context.Context, key string, ttl time.Duration,
	disposition, contentType string) (string, error) {

	out, err := b.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(b.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(disposition),
		ResponseContentType:        aws.String(contentType),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("sign a link to an object: %w", err)
	}
	return out.URL, nil
}

func (b *Bucket) Reachable(ctx context.Context) error {
	if _, err := b.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.bucket),
	}); err != nil {
		return fmt.Errorf("reach object store: %w", err)
	}
	return nil
}
