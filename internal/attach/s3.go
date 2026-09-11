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
	// Whether what reaches this store, and the signed addresses handed out
	// for it, cross the network in the clear. Worked out where the endpoint
	// is checked, so that nothing has to decide it a second time.
	clear bool
}

// BucketConfig is where an object store is and how to reach it.
//
// A struct rather than a parameter list because two of these are booleans that
// sit beside one another, and one of them decides whether attachment links may
// cross a network in the clear. Positional, those two are a security control
// somebody turns off by writing the arguments in the wrong order.
type BucketConfig struct {
	// Endpoint is what a self-hosted store needs and a cloud one does not.
	Endpoint string
	Bucket   string
	Region   string
	Key      string
	Secret   string
	Token    string
	// PathStyle goes with an endpoint: a self-hosted store is usually
	// addressed that way and a provider usually is not.
	PathStyle bool
	// AllowHTTP permits a plaintext endpoint that is not this machine. Off
	// unless an operator says otherwise, because what it exposes is not
	// visible from the configuration that turns it on (REQ-70).
	AllowHTTP bool
}

// NewBucket returns a store, or nil where the deployment configured none .
//
// **Credentials are taken from the environment when none are configured**,
// which is the whole reason for the official client: a deployment on
// a cloud provider gets a role that rotates rather than a long-lived key
// somebody had to put in a variable and then keep.
func NewBucket(ctx context.Context, settings BucketConfig) (*Bucket, error) {
	bucket := strings.TrimSpace(settings.Bucket)
	if bucket == "" {
		return nil, nil
	}
	options := []func(*awsconfig.LoadOptions) error{}
	if region := strings.TrimSpace(settings.Region); region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}
	// Configured credentials win over whatever the environment offers. An
	// operator who names a key means that key, and silently preferring an
	// instance role would be the tool deciding who it is.
	if settings.Key != "" && settings.Secret != "" {
		options = append(options, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(settings.Key, settings.Secret, settings.Token)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("object store credentials: %w", err)
	}
	clear := false
	endpoint := strings.TrimSpace(settings.Endpoint)
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("object store endpoint: %w", err)
		}
		// A presigned URL is a bearer token in an address, and one crossing a
		// network in the clear is a file anybody on the path may fetch — the
		// redirect is the part that leaves us. So plain HTTP is refused unless
		// it reaches no further than this machine, or an operator has said
		// that this network is one they accept it on (REQ-70).
		clear = parsed.Scheme != "https" && !loopback(parsed.Hostname())
		if clear && !settings.AllowHTTP {
			return nil, fmt.Errorf(
				"object store endpoint must be https, or loopback for development: %s", endpoint)
		}
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = settings.PathStyle
	})
	return &Bucket{
		client:  client,
		presign: s3.NewPresignClient(client),
		bucket:  bucket,
		clear:   clear,
	}, nil
}

// InTheClear reports that this store is reached over plain HTTP across a
// network, which an operator allowed. What it costs is said where a deployment
// starts rather than only where it was configured: the address handed to a
// browser carries its own authorization, and the person who set the variable is
// rarely the person reading the logs a year later.
func (b *Bucket) InTheClear() bool { return b.clear }

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
