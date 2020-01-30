############# builder
FROM golang:1.13.4 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-provider-aws
COPY . .
RUN make install-requirements && make VERIFY=true all

############# gardener-extension-provider-aws
FROM alpine:3.11.3 AS gardener-extension-provider-aws

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-provider-aws /gardener-extension-provider-aws
ENTRYPOINT ["/gardener-extension-provider-aws"]

############# gardener-extension-validator-aws
FROM alpine:3.11.3 AS gardener-extension-validator-aws

COPY --from=builder /go/bin/gardener-extension-validator-aws /gardener-extension-validator-aws
ENTRYPOINT ["/gardener-extension-validator-aws"]
