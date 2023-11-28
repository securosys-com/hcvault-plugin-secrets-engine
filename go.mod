module secretengine

go 1.16

replace securosys.ch/helpers => ./helpers

replace securosys.ch/backend => ./backend

replace securosys.ch/client => ./client

replace securosys.ch/test-helpers => ./testHelpers
replace securosys.ch/tests => ./tests

require (
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/vault/api v1.9.1
	github.com/hashicorp/vault/sdk v0.9.1
	github.com/stretchr/testify v1.8.4
	securosys.ch/backend v0.0.0-00010101000000-000000000000
	securosys.ch/helpers v0.0.0-00010101000000-000000000000
	securosys.ch/test-helpers v0.0.0-00010101000000-000000000000
)
