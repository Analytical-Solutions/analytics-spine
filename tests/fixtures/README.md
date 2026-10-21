# Synthetic verifier fixtures

All content is synthetic and test-only. There are no customer records, genuine
approvals or publisher credentials. The manifest's source object ID and external
decision digests are dummy commitments. `curated-commercial` exercises the default
production-format branch; it does not assert a commercial licence exists.

The valid fixture's manifest, signature template and payload are committed literal
bytes. Tests copy them to an OS temporary directory and replace only the signature
template with a signature made by a newly generated in-memory Ed25519 keypair.
Private keys are never serialized. Negative fixture values are literal JSON.
