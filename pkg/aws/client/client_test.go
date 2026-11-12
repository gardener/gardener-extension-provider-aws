// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// roundTripFunc lets us stub the S3 HTTP transport so CreateBucket's error mapping
// can be exercised without reaching AWS.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newS3ClientWithResponse(statusCode int, body string) s3.Client {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: statusCode,
				Header:     http.Header{"Content-Type": []string{"application/xml"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}),
	}

	return *s3.New(s3.Options{
		Region:      "eu-west-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  httpClient,
		// Avoid retrying the error response so the test stays fast and deterministic.
		RetryMaxAttempts: 1,
	})
}

type response struct {
	statusCode int
	body       string
}

// newS3ClientWithResponses returns an S3 client whose HTTP transport serves each
// entry in responses in order. Once the list is exhausted every subsequent call
// returns the last entry, so tests don't have to enumerate every possible
// follow-up request.
func newS3ClientWithResponses(responses []response) (s3.Client, *atomic.Int32) {
	var callCount atomic.Int32
	httpClient := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			idx := int(callCount.Add(1)) - 1
			if idx >= len(responses) {
				idx = len(responses) - 1
			}
			r := responses[idx]
			return &http.Response{
				StatusCode: r.statusCode,
				Header:     http.Header{"Content-Type": []string{"application/xml"}},
				Body:       io.NopCloser(strings.NewReader(r.body)),
			}, nil
		}),
	}
	return *s3.New(s3.Options{
		Region:           "eu-west-1",
		Credentials:      aws.AnonymousCredentials{},
		HTTPClient:       httpClient,
		RetryMaxAttempts: 1,
	}), &callCount
}

var _ = Describe("DeleteBucketIfExists", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("non-versioned bucket", func() {
		It("should succeed when the bucket does not exist", func() {
			body := `<?xml version="1.0" encoding="UTF-8"?>` +
				`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>`
			c := &awsclient.Client{S3: newS3ClientWithResponse(http.StatusNotFound, body)}

			Expect(c.DeleteBucketIfExists(ctx, "test-bucket", "")).To(Succeed())
		})

		It("should succeed when the bucket is already empty", func() {
			// DeleteBucket returns 204 No Content on success.
			c := &awsclient.Client{S3: newS3ClientWithResponse(http.StatusNoContent, "")}

			Expect(c.DeleteBucketIfExists(ctx, "test-bucket", "")).To(Succeed())
		})

		It("should return an error immediately when objects are protected by object lock", func() {
			// Request sequence:
			//   1. DeleteBucket          → 409 BucketNotEmpty
			//   2. GetBucketVersioning   → 200 (versioning not enabled)
			//   3. ListObjectsV2         → 200 one object
			//   4. DeleteObjects         → 200 with per-object AccessDenied error (object lock)
			s3Client, callCount := newS3ClientWithResponses([]response{
				{
					http.StatusConflict,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<Error><Code>BucketNotEmpty</Code><Message>The bucket you tried to delete is not empty.</Message></Error>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration/>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<ListBucketResult>` +
						`<IsTruncated>false</IsTruncated>` +
						`<Contents><Key>backup/snapshot-1</Key></Contents>` +
						`</ListBucketResult>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<DeleteResult>` +
						`<Error><Key>backup/snapshot-1</Key><Code>AccessDenied</Code>` +
						`<Message>Access Denied</Message></Error>` +
						`</DeleteResult>`,
				},
			})
			c := &awsclient.Client{S3: s3Client}

			err := c.DeleteBucketIfExists(ctx, "test-bucket", "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("backup/snapshot-1"))
			Expect(err.Error()).To(ContainSubstring("AccessDenied"))
			// Must not recurse: exactly 4 HTTP calls expected.
			Expect(callCount.Load()).To(BeNumerically("==", 4))
		})
	})

	Context("versioned bucket", func() {
		It("should return an error immediately when object versions are protected by object lock", func() {
			// Request sequence:
			//   1. DeleteBucket          → 409 BucketNotEmpty
			//   2. GetBucketVersioning   → 200 Enabled
			//   3. ListObjectVersions    → 200 one version
			//   4. DeleteObjects (versions) → 200 with per-object error
			s3Client, callCount := newS3ClientWithResponses([]response{
				{
					http.StatusConflict,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<Error><Code>BucketNotEmpty</Code><Message>The bucket you tried to delete is not empty.</Message></Error>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<ListVersionsResult>` +
						`<IsTruncated>false</IsTruncated>` +
						`<Version><Key>backup/snapshot-1</Key><VersionId>v1</VersionId></Version>` +
						`</ListVersionsResult>`,
				},
				{
					http.StatusOK,
					`<?xml version="1.0" encoding="UTF-8"?>` +
						`<DeleteResult>` +
						`<Error><Key>backup/snapshot-1</Key><Code>ObjectLockInvalidHeaders</Code>` +
						`<Message>Object lock is configured for this key.</Message></Error>` +
						`</DeleteResult>`,
				},
			})
			c := &awsclient.Client{S3: s3Client}

			err := c.DeleteBucketIfExists(ctx, "test-bucket", "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("backup/snapshot-1"))
			Expect(err.Error()).To(ContainSubstring("ObjectLockInvalidHeaders"))
			// Must not recurse: exactly 4 HTTP calls expected.
			Expect(callCount.Load()).To(BeNumerically("==", 4))
		})
	})
})

var _ = Describe("CreateBucket", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("when the bucket is already owned by another AWS account", func() {
		It("should return an error classified as ErrorConfigurationProblem", func() {
			// S3 signals a name taken in a foreign account with a 409 BucketAlreadyExists.
			body := `<?xml version="1.0" encoding="UTF-8"?>` +
				`<Error><Code>BucketAlreadyExists</Code>` +
				`<Message>The requested bucket name is not available.</Message></Error>`
			c := &awsclient.Client{S3: newS3ClientWithResponse(http.StatusConflict, body)}

			err := c.CreateBucket(ctx, "some-bucket", "eu-west-1", "123456789012", false)
			Expect(err).To(HaveOccurred())

			// Run the error through the same classification the actuator uses.
			determined := util.DetermineError(err, helper.KnownCodes)
			Expect(v1beta1helper.ExtractErrorCodes(determined)).To(ContainElement(gardencorev1beta1.ErrorConfigurationProblem))
		})
	})
})
