FROM goreleaser/goreleaser as build

ADD . /go/src/github.com/cludden/terraform-registry
WORKDIR /go/src/github.com/cludden/terraform-registry
RUN goreleaser build --rm-dist --snapshot



FROM alpine:edge
RUN addgroup -S terraform && adduser -S terraform -G terraform
RUN apk update && apk upgrade && apk add tzdata ca-certificates

COPY --from=build --chown=terraform:terraform /go/src/github.com/cludden/terraform-registry/dist/terraform-registry_linux_amd64/terraform-registry /terraform-registry

USER terraform
ENTRYPOINT ["/terraform-registry"]
