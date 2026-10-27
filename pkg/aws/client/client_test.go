// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"io"
	"net/http"
	"strings"

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
