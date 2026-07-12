package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func TestCollect_ParsesAttestationAndAppliesMaxAge(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ropa-v1.yaml"), []byte(`kind: ropa
schema: ropa-v1
version: "1"
owner: dpo@acme.com
signers: [dpo@acme.com]
last_review_at: "2026-05-01T00:00:00Z"
expires_at: "2027-05-01T00:00:00Z"
attested_fields:
  scope: all EU customer data
  lawful_basis: contract
  retention: 7y
`), 0o644))

	c := Collector{}
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":       "ropa-v1",
			"path":         filepath.Join(dir, "ropa-v1.yaml"),
			"max_age_days": 365,
			"signers":      []any{"dpo@acme.com"},
		},
	})
	require.NoError(t, err)
	m, ok := out.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ropa", m["kind"])
	assert.Equal(t, "ropa-v1", m["schema"])
	assert.Equal(t, "dpo@acme.com", m["owner"])
	assert.Equal(t, "", m["staleness_note"], "fresh attestation should not be flagged stale")
	assert.Equal(t, "", m["signer_warning"], "matching signer should not warn")

	// attested_fields is a structured map (the contract the control packs read),
	// not a list of field names.
	af, ok := m["attested_fields"].(map[string]any)
	require.True(t, ok, "attested_fields must be an object")
	assert.Equal(t, "contract", af["lawful_basis"])
}

func TestCollect_FlagsStaleAttestation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dpia-v1.yaml"), []byte(`kind: dpia
schema: dpia-v1
version: "1"
owner: dpo@acme.com
signers: [dpo@acme.com]
last_review_at: "2023-01-01T00:00:00Z"
expires_at: "2024-01-01T00:00:00Z"
attested_fields:
  scope: high-risk profiling
`), 0o644))

	c := Collector{}
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":       "dpia-v1",
			"path":         filepath.Join(dir, "dpia-v1.yaml"),
			"max_age_days": 365,
		},
	})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.NotEmpty(t, m["staleness_note"])
}

func TestCollect_WarnsWhenRequiredSignerAbsent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dpa-v1.yaml"), []byte(`kind: dpa
schema: dpa-v1
version: "1"
owner: legal@acme.com
signers: [legal@acme.com]
last_review_at: "2026-05-01T00:00:00Z"
attested_fields:
  parties: [Acme, Vendor]
  term: 2y
`), 0o644))

	c := Collector{}
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":  "dpa-v1",
			"path":    filepath.Join(dir, "dpa-v1.yaml"),
			"signers": []any{"dpo@acme.com"},
		},
	})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.NotEmpty(t, m["signer_warning"])
}

func TestCollect_VerifiesEd25519Signature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "ropa-v1.yaml")
	body := `kind: ropa
schema: ropa-v1
version: "1"
owner: dpo@acme.com
signers: [dpo@acme.com]
last_review_at: "2026-05-01T00:00:00Z"
expires_at: "2027-05-01T00:00:00Z"
attested_fields:
  scope: all EU customer data
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	// Sign the canonical bytes of the parsed attestation (signature excluded),
	// exactly as a signing tool would, then embed the signature.
	att, err := loadAttestation(path, "ropa-v1")
	require.NoError(t, err)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signableBytes(att)))
	require.NoError(t, os.WriteFile(path, []byte(body+fmt.Sprintf("signature: %q\n", sig)), 0o644))

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	c := Collector{}

	// Trusted key present -> verified.
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":      "ropa-v1",
			"path":        path,
			"public_keys": []any{pubB64},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, true, out.(map[string]any)["signature_verified"])

	// No trusted keys configured -> fails closed.
	out, err = c.Collect(context.Background(), plugin.EvidenceRef{
		Type:   "policy_attestation",
		Params: map[string]any{"schema": "ropa-v1", "path": path},
	})
	require.NoError(t, err)
	assert.Equal(t, false, out.(map[string]any)["signature_verified"])

	// A different (untrusted) key -> not verified.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	out, err = c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":      "ropa-v1",
			"path":        path,
			"public_keys": []any{base64.StdEncoding.EncodeToString(otherPub)},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, false, out.(map[string]any)["signature_verified"])
}

func TestCollect_UnsignedNotVerified(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "ropa-v1.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`kind: ropa
schema: ropa-v1
attested_fields:
  scope: all EU customer data
`), 0o644))

	c := Collector{}
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema":      "ropa-v1",
			"path":        path,
			"public_keys": []any{base64.StdEncoding.EncodeToString(pub)},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, false, out.(map[string]any)["signature_verified"],
		"an attestation with no signature must never be reported verified")
}

func TestCollect_RejectsUnsupportedType(t *testing.T) {
	c := Collector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "other"})
	assert.ErrorIs(t, err, plugin.ErrUnsupportedType)
}

func TestCollect_RequiresSchemaParam(t *testing.T) {
	c := Collector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "policy_attestation"})
	require.Error(t, err)
}

func TestCollect_RejectsSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.yaml"),
		[]byte("schema: other-v1\nversion: \"1\"\n"), 0o644))
	c := Collector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema": "expected-v1",
			"path":   filepath.Join(dir, "x.yaml"),
		},
	})
	require.Error(t, err)
}
