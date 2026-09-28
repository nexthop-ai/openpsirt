// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
	// The endpoint with any password taken out, which is the only form of it
	// that is written down. Kept because it is parsed here anyway, so nothing
	// downstream has to parse it again to say where the store is.
	endpoint string
	// Whatever reaches this store, and the signed addresses handed out
	// for it, cross the network in the clear. Worked out where the endpoint
	// is checked, so that nothing has to decide it a second time.
	clear bool
	// The store is reached over plain HTTP, whether across a network or on
	// this machine. An upload is a stream with no Seek, and over plain HTTP
	// the client cannot hash or checksum one ahead of sending it.
	plain bool
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

// NewBucket returns a store, or nil where the deployment configured none.
//
// Credentials are taken from the environment when none are configured,
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
	inTheClear, plain := false, false
	endpoint := strings.TrimSpace(settings.Endpoint)
	shown := endpoint
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("object store endpoint: %w", err)
		}
		// A name and password in the address are taken out of it and handed
		// over as credentials, which is also what makes the signing
		// well-defined. The client is given the address without them, because
		// every failure it reports carries the address it was given, and a
		// startup reachability failure is printed to standard error, where a
		// container runtime captures it into a log store.
		//
		// A configured key still wins, for the reason above.
		if parsed.User != nil {
			if settings.Key == "" && settings.Secret == "" {
				password, _ := parsed.User.Password()
				options = append(options, awsconfig.WithCredentialsProvider(
					credentials.NewStaticCredentialsProvider(
						parsed.User.Username(), password, settings.Token)))
			}
			parsed.User = nil
			endpoint = parsed.String()
		}
		// A presigned URL is a bearer token in an address, and one crossing a
		// network in the clear is a file anybody on the path may fetch — the
		// redirect is the part that leaves us. So plain HTTP is refused unless
		// it reaches no further than this machine, or an operator has said
		// that this network is one they accept it on (REQ-70).
		// The string shown and the string used are one, rather
		// than two that can drift: the password has already been taken out
		// of the one the client gets.
		shown = endpoint
		plain = parsed.Scheme != "https"
		inTheClear = plain && !loopback(parsed.Hostname())
		if inTheClear && !settings.AllowHTTP {
			// Naming the way through. The operator meeting this is the one a
			// plaintext store was allowed for, and a refusal that states only
			// what is forbidden leaves them to find the setting by reading the
			// source.
			return nil, fmt.Errorf(
				"object store endpoint must be https, or loopback for development: %s"+
					" — set OPENPSIRT_ATTACHMENT_ALLOW_HTTP to accept it on this network",
				shown)
		}
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("object store credentials: %w", err)
	}
	// The address guard does not apply here, deliberately. Everything the
	// guard exists for is an address that arrived from outside: a sign-in
	// provider's endpoints come from a discovery document somebody else
	// publishes, so they are pinned, refused a redirect and refused an
	// address inside this network. An object-store endpoint was typed in by
	// the operator, and pointing it at something on their own network — a
	// MinIO on this host, storage on the next rack — is the ordinary
	// deployment rather than the attack. Routing it through the guard would
	// refuse that and protect against nothing.
	//
	// The cost of the exemption, which is less than it sounds: the endpoint is
	// read from the environment once, at startup, and no administrator can
	// change it from inside the application. So aiming these requests
	// anywhere is something whoever deploys the process can already do by
	// other means, and the control is who may deploy it.
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = settings.PathStyle
	})
	return &Bucket{
		client:   client,
		presign:  s3.NewPresignClient(client),
		bucket:   bucket,
		endpoint: shown,
		clear:    inTheClear,
		plain:    plain,
	}, nil
}

// InTheClear reports that this store is reached over plain HTTP across a
// network, which an operator allowed. What it costs is said where a deployment
// starts rather than only where it was configured: the address handed to a
// browser carries its own authorization, and the person who set the variable is
// rarely the person reading the logs a year later.
func (b *Bucket) InTheClear() bool { return b.clear }

// Endpoint is where this store is, with any password taken out. Empty for a
// cloud provider, which is addressed by region rather than by name.
func (b *Bucket) Endpoint() string { return b.endpoint }

// loopback says whether a host reaches no further than this machine.
//
// Loopback is the whole of 127.0.0.0/8 and ::1 in every spelling, including
// the IPv4-mapped IPv6 forms, so it is asked of the parsed address rather than
// matched against a list of spellings.
//
// The literal name stays, because it is a name rather than an address and the
// deployment may have it in its own hosts file.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	// Belt and braces: Hostname() already strips the brackets from an IPv6
	// literal, and a caller that has not been through it has not.
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (b *Bucket) Name() string { return "s3" }

func (b *Bucket) Put(ctx context.Context, key string, body io.Reader, size int64,
	contentType string) error {

	// Streamed rather than held. The signature covers the envelope and TLS
	// covers the bytes, which is what lets a reader be passed through instead
	// of a slice the size of the file.
	//
	// Over https the client sends a trailing checksum, which a stream
	// satisfies. Over plain HTTP it would hash the body before sending it,
	// which a stream with no Seek refuses, so the payload goes unsigned and
	// the checksum is sent only where the operation requires one. The body's
	// integrity is the upload path's own digest, taken as the bytes pass.
	var perCall []func(*s3.Options)
	if b.plain {
		perCall = append(perCall,
			s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
			func(o *s3.Options) {
				o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			})
	}
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	}, perCall...)
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
