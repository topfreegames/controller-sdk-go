FROM quay.io/deis/go-dev:v1.12.2
# This Dockerfile is used to bundle the source and all dependencies into an image for testing.

ADD https://codecov.io/bash /usr/local/bin/codecov
RUN chmod +x /usr/local/bin/codecov

COPY Gopkg.lock /go/src/github.com/deis/controller-sdk-go/Gopkg.lock
COPY Gopkg.toml /go/src/github.com/deis/controller-sdk-go/Gopkg.toml

WORKDIR /go/src/github.com/deis/controller-sdk-go

RUN dep ensure --vendor-only

COPY . /go/src/github.com/deis/controller-sdk-go

COPY ./_scripts /usr/local/bin
