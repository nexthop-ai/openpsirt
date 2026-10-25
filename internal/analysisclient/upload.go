// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Target is where a run is sent, and the key it is sent with.
type Target struct {
	URL, Key                 string
	Product, Stream, Variant string
}

// Fields is what is sent beside the document: the values the deployment
// reads from the request alone.
type Fields struct {
	// Rules is the rules enabled.
	Rules []string
	// ThirdParty is the paths, relative to the checkout, holding code the
	// product did not write.
	ThirdParty []string
}

// Answer is the deployment's response to an upload.
type Answer struct {
	Status int
	Body   []byte
}

// attempts is how many times an upload is sent while the deployment answers
// that it is busy, or cannot be reached.
const attempts = 5

// longestWait bounds how long one wait between attempts may be, whatever
// the deployment asks for.
const longestWait = 2 * time.Minute

// Send uploads a document, compressed, with its fields. A deployment that
// answers 503 is asked again after the time it names, and one that cannot be
// reached after a pause that doubles; any other answer is returned as it came.
func Send(ctx context.Context, client *http.Client, to Target, doc []byte, fields Fields) (Answer, error) {
	address, err := analysesURL(to)
	if err != nil {
		return Answer{}, err
	}
	body, contentType, err := form(doc, fields)
	if err != nil {
		return Answer{}, err
	}
	pause := 2 * time.Second
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
		if err != nil {
			return Answer{}, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+to.Key)
		resp, err := client.Do(req)
		wait := pause
		if err == nil {
			said, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable || attempt == attempts {
				return Answer{Status: resp.StatusCode, Body: said}, readErr
			}
			if s, convErr := strconv.Atoi(resp.Header.Get("Retry-After")); convErr == nil && s >= 0 {
				wait = time.Duration(s) * time.Second
			}
		} else if attempt == attempts || errors.Is(err, context.Canceled) {
			return Answer{}, err
		}
		select {
		case <-ctx.Done():
			return Answer{}, ctx.Err()
		case <-time.After(min(wait, longestWait)):
		}
		pause *= 2
	}
}

// analysesURL is the operation a build's analyzer runs are sent to.
func analysesURL(to Target) (string, error) {
	base, err := url.Parse(strings.TrimSuffix(to.URL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return "", fmt.Errorf("%q is not the address of a deployment", to.URL)
	}
	for _, part := range []struct{ name, value string }{
		{"product", to.Product}, {"stream", to.Stream}, {"variant", to.Variant},
	} {
		if part.value == "" {
			return "", fmt.Errorf("a run is sent for a product, a stream and a variant, and names no %s", part.name)
		}
	}
	return base.String() + "/v1/products/" + url.PathEscape(to.Product) +
		"/streams/" + url.PathEscape(to.Stream) +
		"/variants/" + url.PathEscape(to.Variant) + "/analyses", nil
}

// form is the request body: the document, compressed, and the fields.
func form(doc []byte, fields Fields) ([]byte, string, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	head := textproto.MIMEHeader{}
	head.Set("Content-Disposition", `form-data; name="sarif"; filename="run.sarif.gz"`)
	head.Set("Content-Type", "application/gzip")
	part, err := w.CreatePart(head)
	if err != nil {
		return nil, "", err
	}
	z := gzip.NewWriter(part)
	if _, err := z.Write(doc); err != nil {
		return nil, "", err
	}
	if err := z.Close(); err != nil {
		return nil, "", err
	}
	for _, f := range []struct {
		name   string
		values []string
	}{{"rules", fields.Rules}, {"third-party", fields.ThirdParty}} {
		for _, v := range f.values {
			if err := w.WriteField(f.name, v); err != nil {
				return nil, "", err
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), w.FormDataContentType(), nil
}
