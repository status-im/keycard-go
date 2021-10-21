module github.com/status-im/keycard-go

go 1.17

require (
	github.com/status-im/go-ethereum v1.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/text v0.3.7
)

require (
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ethereum/go-ethereum v1.10.4 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20210816183151-1e6c022a8912 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/ethereum/go-ethereum v1.10.4 => github.com/status-im/go-ethereum v1.10.4-status.2
