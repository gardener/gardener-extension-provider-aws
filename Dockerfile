############# builder
FROM golang:1.22.1 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-provider-aws

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG EFFECTIVE_VERSION

RUN make install EFFECTIVE_VERSION=$EFFECTIVE_VERSION

############# base
FROM gcr.io/distroless/static-debian11:nonroot AS base

############# gardener-extension-provider-aws
FROM base AS gardener-extension-provider-aws
WORKDIR /

COPY --from=builder /go/bin/gardener-extension-provider-aws /gardener-extension-provider-aws
ENTRYPOINT ["/gardener-extension-provider-aws"]

############# gardener-extension-admission-aws
FROM base as gardener-extension-admission-aws
WORKDIR /

COPY --from=builder /go/bin/gardener-extension-admission-aws /gardener-extension-admission-aws
ENTRYPOINT ["/gardener-extension-admission-aws"]
