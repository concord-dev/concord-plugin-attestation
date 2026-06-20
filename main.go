// concord-plugin-attestation reads signed YAML attestations from disk and emits structured evidence.
package main

import (
	"context"
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
	version = "v0.1.0"
)

type attestationCollector struct{}

func (attestationCollector) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{
		Source:         source,
		Version:        version,
		SupportedTypes: []string{"policy_attestation"},
		OptionalEnv:    []string{"CONCORD_ATTESTATION_DIR"},
		DocsURL:        "https://github.com/concord-dev/concord-plugin-attestation",
		Permissions: plugin.Permissions{
			Filesystem: "read-only",
		},
	}
}

func (attestationCollector) Probe(_ context.Context) (string, error) {
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

func (attestationCollector) Collect(_ context.Context, ref plugin.EvidenceRef) (any, error) {
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
	return map[string]any{
		"fetched_at":      time.Now().UTC().Format(time.RFC3339),
		"schema":          att.Schema,
		"version":         att.Version,
		"owner":           att.Owner,
		"signers":         att.Signers,
		"last_review_at":  rfcTime(att.LastReviewAt),
		"expires_at":      rfcTime(att.ExpiresAt),
		"attested_fields": att.AttestedFields,
		"path":            att.Path,
		"staleness_note":  att.StalenessNote,
		"signer_warning":  att.SignerWarning,
	}, nil
}

type attestation struct {
	Path           string    `json:"path"`
	Schema         string    `json:"schema"`
	Version        string    `json:"version"`
	Owner          string    `json:"owner"`
	Signers        []string  `json:"signers"`
	LastReviewAt   time.Time `json:"-"`
	LastReviewRaw  string    `json:"last_review_at"`
	ExpiresAt      time.Time `json:"-"`
	ExpiresRaw     string    `json:"expires_at"`
	AttestedFields []string  `json:"attested_fields"`
	StalenessNote  string    `json:"-"`
	SignerWarning  string    `json:"-"`
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
		Schema         string   `json:"schema" yaml:"schema"`
		Version        string   `json:"version" yaml:"version"`
		Owner          string   `json:"owner" yaml:"owner"`
		Signers        []string `json:"signers" yaml:"signers"`
		LastReviewAt   string   `json:"last_review_at" yaml:"last_review_at"`
		ExpiresAt      string   `json:"expires_at" yaml:"expires_at"`
		AttestedFields []string `json:"attested_fields" yaml:"attested_fields"`
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
		Schema:         schema,
		Version:        doc.Version,
		Owner:          doc.Owner,
		Signers:        doc.Signers,
		LastReviewRaw:  doc.LastReviewAt,
		ExpiresRaw:     doc.ExpiresAt,
		AttestedFields: doc.AttestedFields,
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

func main() { plugin.Serve(attestationCollector{}) }
