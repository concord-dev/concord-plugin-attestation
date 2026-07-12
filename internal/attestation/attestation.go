// Package attestation reads signed YAML attestations from disk and emits structured evidence.
package attestation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
	"sigs.k8s.io/yaml"
)

const (
	source  = "attestation"
	version = "v0.2.0"
)

// pubKeysEnv names the environment variable holding the operator's trusted
// Ed25519 attestation-signing public keys (base64, whitespace- or
// comma-separated). A signature verifies only against a key listed here.
const pubKeysEnv = "CONCORD_ATTESTATION_PUBKEYS"

// Collector answers the "policy_attestation" evidence type by reading signed
// YAML attestations from disk.
type Collector struct{}

// New returns an attestation collector.
func New() *Collector { return &Collector{} }

func (Collector) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{
		Source:         source,
		Version:        version,
		SupportedTypes: []string{"policy_attestation"},
		OptionalEnv:    []string{"CONCORD_ATTESTATION_DIR", pubKeysEnv},
		DocsURL:        "https://github.com/concord-dev/concord-plugin-attestation",
		Permissions: plugin.Permissions{
			Filesystem: "read-only",
		},
	}
}

func (Collector) Probe(_ context.Context) (string, error) {
	dir := os.Getenv("CONCORD_ATTESTATION_DIR")
	if dir == "" {
		dir = filepath.Join(".", "attestations")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("attestation directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("attestation path %s is not a directory", dir)
	}
	return fmt.Sprintf("attestation plugin OK (root=%s)", dir), nil
}

func (Collector) Collect(_ context.Context, ref plugin.EvidenceRef) (any, error) {
	if ref.Type != "policy_attestation" {
		return nil, plugin.ErrUnsupportedType
	}
	schema := plugin.StringParam(ref, "schema")
	if schema == "" {
		return nil, errors.New("attestation: params.schema is required (e.g. ropa-v1, dpia-v1)")
	}
	maxAge := plugin.IntParam(ref, "max_age_days")
	signers := stringListParam(ref, "signers")
	path := plugin.StringParam(ref, "path")

	att, err := loadAttestation(path, schema)
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && !att.LastReviewAt.IsZero() {
		if time.Since(att.LastReviewAt) > time.Duration(maxAge)*24*time.Hour {
			att.StalenessNote = fmt.Sprintf("attestation last reviewed %s; threshold is %d days",
				att.LastReviewAt.Format(time.RFC3339), maxAge)
		}
	}
	if len(signers) > 0 {
		if !signedByAny(att.Signers, signers) {
			att.SignerWarning = fmt.Sprintf("none of the required signers %v signed this attestation", signers)
		}
	}
	att.SignatureVerified = verifySignature(signableBytes(att), att.Signature, trustedPublicKeys(ref))

	attested := att.AttestedFields
	if attested == nil {
		attested = map[string]any{}
	}
	return map[string]any{
		"fetched_at":         time.Now().UTC().Format(time.RFC3339),
		"kind":               att.Kind,
		"schema":             att.Schema,
		"version":            att.Version,
		"owner":              att.Owner,
		"signers":            att.Signers,
		"last_review_at":     rfcTime(att.LastReviewAt),
		"expires_at":         rfcTime(att.ExpiresAt),
		"attested_fields":    attested,
		"signature_verified": att.SignatureVerified,
		"path":               att.Path,
		"staleness_note":     att.StalenessNote,
		"signer_warning":     att.SignerWarning,
	}, nil
}

type attestation struct {
	Path              string
	Kind              string
	Schema            string
	Version           string
	Owner             string
	Signers           []string
	LastReviewAt      time.Time
	LastReviewRaw     string
	ExpiresAt         time.Time
	ExpiresRaw        string
	AttestedFields    map[string]any
	Signature         string
	SignatureVerified bool
	StalenessNote     string
	SignerWarning     string
}

func loadAttestation(path, schema string) (attestation, error) {
	var att attestation
	if path == "" {
		dir := os.Getenv("CONCORD_ATTESTATION_DIR")
		if dir == "" {
			dir = "attestations"
		}
		path = filepath.Join(dir, schema+".yaml")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return att, fmt.Errorf("read %s: %w", path, err)
	}
	type onDisk struct {
		Kind           string         `json:"kind" yaml:"kind"`
		Schema         string         `json:"schema" yaml:"schema"`
		Version        string         `json:"version" yaml:"version"`
		Owner          string         `json:"owner" yaml:"owner"`
		Signers        []string       `json:"signers" yaml:"signers"`
		LastReviewAt   string         `json:"last_review_at" yaml:"last_review_at"`
		ExpiresAt      string         `json:"expires_at" yaml:"expires_at"`
		AttestedFields map[string]any `json:"attested_fields" yaml:"attested_fields"`
		Signature      string         `json:"signature" yaml:"signature"`
	}
	var doc onDisk
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return att, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.Schema != "" && doc.Schema != schema {
		return att, fmt.Errorf("attestation %s declares schema %q, requested %q", path, doc.Schema, schema)
	}
	att = attestation{
		Path:           path,
		Kind:           doc.Kind,
		Schema:         schema,
		Version:        doc.Version,
		Owner:          doc.Owner,
		Signers:        doc.Signers,
		LastReviewRaw:  doc.LastReviewAt,
		ExpiresRaw:     doc.ExpiresAt,
		AttestedFields: doc.AttestedFields,
		Signature:      doc.Signature,
	}
	if doc.LastReviewAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.LastReviewAt); err == nil {
			att.LastReviewAt = t
		}
	}
	if doc.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.ExpiresAt); err == nil {
			att.ExpiresAt = t
		}
	}
	return att, nil
}

// signableBytes is the canonical serialisation an attestation's signature
// covers: the deterministic JSON of the content fields, excluding the
// signature itself. encoding/json sorts every map key (recursively), so the
// bytes are stable across the signer and the verifier. A signing tool must
// produce an Ed25519 signature over exactly these bytes.
func signableBytes(att attestation) []byte {
	signable := map[string]any{
		"kind":            att.Kind,
		"schema":          att.Schema,
		"version":         att.Version,
		"owner":           att.Owner,
		"signers":         att.Signers,
		"last_review_at":  att.LastReviewRaw,
		"expires_at":      att.ExpiresRaw,
		"attested_fields": att.AttestedFields,
	}
	b, _ := json.Marshal(signable)
	return b
}

// verifySignature reports whether sig (base64 Ed25519) over signable verifies
// against any trusted public key (base64 Ed25519). It fails closed: an absent
// signature, no configured keys, or a malformed signature/key all return false,
// so an unverifiable attestation is never reported as signature_verified.
func verifySignature(signable []byte, sigB64 string, trustedKeysB64 []string) bool {
	if sigB64 == "" || len(trustedKeysB64) == 0 {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, keyB64 := range trustedKeysB64 {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
		if err != nil || len(key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(key), signable, sig) {
			return true
		}
	}
	return false
}

// trustedPublicKeys collects the operator's trusted signing keys from the
// evidence ref's public_keys param and the CONCORD_ATTESTATION_PUBKEYS env var.
func trustedPublicKeys(ref plugin.EvidenceRef) []string {
	keys := stringListParam(ref, "public_keys")
	if env := strings.TrimSpace(os.Getenv(pubKeysEnv)); env != "" {
		keys = append(keys, strings.Fields(strings.ReplaceAll(env, ",", " "))...)
	}
	return keys
}

func stringListParam(ref plugin.EvidenceRef, key string) []string {
	raw, ok := ref.Params[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func signedByAny(signers, required []string) bool {
	set := make(map[string]struct{}, len(signers))
	for _, s := range signers {
		set[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[strings.ToLower(strings.TrimSpace(r))]; ok {
			return true
		}
	}
	return false
}

func rfcTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
