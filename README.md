# concord-plugin-attestation

Concord collector for the `policy_attestation` evidence kind. Reads signed YAML
attestations from disk and emits the structured shape consumed by
`data.concord.lib.attestation` rules.

Use this for governance / paperwork controls that have no machine-checkable
evidence — DPIAs, ROPAs, DPAs, ISMSs, HIPAA workforce-training acknowledgments,
PCI Req-12 policy reviews.

## Install

```sh
git clone https://github.com/concord-dev/concord-plugin-attestation.git
cd concord-plugin-attestation
make install
```

## Attestation file shape

```yaml
kind: ropa                 # the attestation kind controls read as input.<id>.kind
schema: ropa-v1            # must match params.schema in the control YAML
version: "1"
owner: dpo@acme.com
signers:
  - dpo@acme.com
last_review_at: "2026-05-01T00:00:00Z"
expires_at:    "2027-05-01T00:00:00Z"
attested_fields:           # a structured MAP of the attested content
  scope: all EU customer personal data
  lawful_basis: contract
  retention: 7y
signature: "<base64 Ed25519 signature over the canonical content>"
```

Controls read the emitted payload as `input.<id>.kind`,
`input.<id>.attested_fields.<field>` (a map), and
`input.<id>.signature_verified` (bool), plus the envelope fields (`owner`,
`signers`, `last_review_at`, `expires_at`). This shape is pinned by the
`attestation/policy_attestation` EvidenceType schema.

## Wire to a control

```yaml
spec:
  evidence:
    - id: ropa
      source: attestation
      type: policy_attestation
      params:
        schema: ropa-v1
        signers: ["dpo@acme.com"]
        max_age_days: 365
        path: ./attestations/ropa-v1.yaml   # optional; defaults to $CONCORD_ATTESTATION_DIR
```

Scaffold a matching control + Rego:

```sh
concord scaffold control --pack gdpr --id GDPR-30 --template policy-attestation
```

## Config

| Env var | Default | Meaning |
|---|---|---|
| `CONCORD_ATTESTATION_DIR` | `./attestations` | Root searched when `params.path` is empty |
| `CONCORD_ATTESTATION_PUBKEYS` | _(none)_ | Trusted Ed25519 signing public keys (base64), whitespace- or comma-separated. A signature verifies only against a key listed here (or in `params.public_keys`). |

## Signature verification

`signature_verified` is a real cryptographic check, not an honour system. The
`signature:` field is a base64 **Ed25519** signature over the *canonical
content* of the attestation — the deterministic JSON of every field except
`signature` (`encoding/json` sorts all map keys, so signer and verifier agree
byte-for-byte). The plugin verifies it against the operator's trusted keys
(`params.public_keys` or `CONCORD_ATTESTATION_PUBKEYS`) and **fails closed**: an
absent signature, no configured keys, or an untrusted/invalid signature all
yield `signature_verified: false`, which the attestation controls treat as a
deny.

The `signers:` list and `params.signers` remain an independent, advisory check
(a `signer_warning` when a required approver's name is absent) — orthogonal to
the cryptographic verification.

### Signing an attestation

Sign the canonical content with an Ed25519 private key and embed the base64
signature. The canonical bytes are `json.Marshal` of:

```json
{"attested_fields":{…},"expires_at":"…","kind":"…","last_review_at":"…","owner":"…","schema":"…","signers":[…],"version":"…"}
```

```go
sig := ed25519.Sign(priv, canonicalJSON)        // canonicalJSON as above
signatureField := base64.StdEncoding.EncodeToString(sig)
// distribute base64(pub) to verifiers via CONCORD_ATTESTATION_PUBKEYS
```
