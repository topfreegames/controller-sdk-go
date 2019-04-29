FROM quay.io/deis/go-dev:v1.12.2
# This Dockerfile is used to bundle the source and all dependencies into an image for testing.

ADD https://codecov.io/bash /usr/local/bin/codecov
RUN chmod +x /usr/local/bin/codecov

COPY . /go/src/github.com/deis/controller-sdk-go

WORKDIR /go/src/github.com/deis/controller-sdk-go

RUN dep ensure

COPY ./_scripts /usr/local/bin
