############# builder
FROM golang:1.14.9 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-provider-aws
COPY . .
RUN make install

############# base
FROM alpine:3.12.0 AS base

############# gardener-extension-provider-aws
FROM base AS gardener-extension-provider-aws

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-provider-aws /gardener-extension-provider-aws
ENTRYPOINT ["/gardener-extension-provider-aws"]

############# gardener-extension-validator-aws
FROM base AS gardener-extension-validator-aws

COPY --from=builder /go/bin/gardener-extension-validator-aws /gardener-extension-validator-aws
ENTRYPOINT ["/gardener-extension-validator-aws"]
