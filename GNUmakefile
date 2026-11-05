default: build

build:
	go build ./...

lint:
	gofmt -l . | (! grep .)
	go vet ./...

# Unit tests and resource tests run against an in-memory fake of dns-gate
# (internal/fakegate) with the terraform binary found in PATH: no gate, no
# credentials, no network. Acceptance tests against a real gate: make testacc.
test:
	go test -count=1 ./...

test-tofu:
	TF_ACC_TERRAFORM_PATH=$$(command -v tofu) TF_ACC_PROVIDER_HOST=registry.opentofu.org go test -count=1 ./...

testacc:
	TF_ACC=1 go test -count=1 -run '^TestAcc' -v ./internal/provider/

docs:
	go generate ./...

install:
	go install .

.PHONY: default build lint test test-tofu testacc docs install
