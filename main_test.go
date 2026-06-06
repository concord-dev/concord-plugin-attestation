package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord/pkg/plugin"
)

func TestCollect_ParsesAttestationAndAppliesMaxAge(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ropa-v1.yaml"), []byte(`schema: ropa-v1
version: "1"
owner: dpo@acme.com
signers: [dpo@acme.com]
last_review_at: "2026-05-01T00:00:00Z"
expires_at: "2027-05-01T00:00:00Z"
attested_fields: [scope, lawful_basis, retention]
`), 0o644))

	c := attestationCollector{}
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
	assert.Equal(t, "ropa-v1", m["schema"])
	assert.Equal(t, "dpo@acme.com", m["owner"])
	assert.Equal(t, "", m["staleness_note"], "fresh attestation should not be flagged stale")
	assert.Equal(t, "", m["signer_warning"], "matching signer should not warn")
}

func TestCollect_FlagsStaleAttestation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dpia-v1.yaml"), []byte(`schema: dpia-v1
version: "1"
owner: dpo@acme.com
signers: [dpo@acme.com]
last_review_at: "2023-01-01T00:00:00Z"
expires_at: "2024-01-01T00:00:00Z"
attested_fields: [scope]
`), 0o644))

	c := attestationCollector{}
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
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dpa-v1.yaml"), []byte(`schema: dpa-v1
version: "1"
owner: legal@acme.com
signers: [legal@acme.com]
last_review_at: "2026-05-01T00:00:00Z"
attested_fields: [parties, term]
`), 0o644))

	c := attestationCollector{}
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

func TestCollect_RejectsUnsupportedType(t *testing.T) {
	c := attestationCollector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "other"})
	assert.ErrorIs(t, err, plugin.ErrUnsupportedType)
}

func TestCollect_RequiresSchemaParam(t *testing.T) {
	c := attestationCollector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "policy_attestation"})
	require.Error(t, err)
}

func TestCollect_RejectsSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.yaml"),
		[]byte("schema: other-v1\nversion: \"1\"\n"), 0o644))
	c := attestationCollector{}
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type: "policy_attestation",
		Params: map[string]any{
			"schema": "expected-v1",
			"path":   filepath.Join(dir, "x.yaml"),
		},
	})
	require.Error(t, err)
}
