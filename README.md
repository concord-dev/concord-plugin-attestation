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
schema: ropa-v1            # must match params.schema in the control YAML
version: "1"
owner: dpo@acme.com
signers:
  - dpo@acme.com
last_review_at: "2026-05-01T00:00:00Z"
expires_at:    "2027-05-01T00:00:00Z"
attested_fields:
  - scope
  - lawful_basis
  - retention
```

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

## Signature verification

Today the plugin checks that one of the named signers appears in the
attestation's `signers:` list. Future versions will verify a detached
cosign signature alongside the YAML; the wire shape is forward-compatible.
