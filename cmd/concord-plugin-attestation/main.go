// Command concord-plugin-attestation reads signed YAML attestations from disk and emits structured evidence.
package main

import (
	"github.com/concord-dev/concord-plugin-attestation/internal/attestation"
	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func main() { plugin.Serve(attestation.New()) }
