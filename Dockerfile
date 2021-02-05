############# builder
FROM eu.gcr.io/gardener-project/3rd/golang:1.15.5 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-provider-aws
COPY . .
RUN make install

############# base
FROM eu.gcr.io/gardener-project/3rd/alpine:3.12.3 AS base

############# gardener-extension-provider-aws
FROM base AS gardener-extension-provider-aws

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-provider-aws /gardener-extension-provider-aws
ENTRYPOINT ["/gardener-extension-provider-aws"]

############# gardener-extension-admission-aws
FROM base as gardener-extension-admission-aws

COPY --from=builder /go/bin/gardener-extension-admission-aws /gardener-extension-admission-aws
ENTRYPOINT ["/gardener-extension-admission-aws"]
