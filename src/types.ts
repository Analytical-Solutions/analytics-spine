import type { KeyObject } from 'node:crypto';

export interface PackFile {
  path: string;
  sha256: string;
  bytes: number;
  role: 'process' | 'source-map' | 'oracle-template' | 'contract' | 'scenario' | 'notice' | 'proof-reference';
}

export interface Manifest {
  kind: 'analytics-spine-domain-pack';
  schemaVersion: 1;
  id: string;
  version: string;
  classification: 'curated-commercial' | 'public-fixture';
  erp: { id: string; version: string; sourceSchemaDigest: string };
  processes: string[];
  engine: { minimumVersion: string; maximumExclusiveVersion: string };
  licence: { record: 'OD-LEGAL'; decisionDigest: string; documentDigest: string; noticePaths: string[] };
  provenance: { record: 'OD-HARVEST'; decisionDigest: string; reviewDigest: string };
  files: PackFile[];
  proof: { catalogueDigest: string; expectationsDigest: string; resultsDigest: string; attestationDigest: string; sourceHead: string };
  claims: { id: string; scenarioIds: string[]; scopeDigest: string }[];
}

export interface PackSignature {
  kind: 'analytics-spine-pack-signature';
  schemaVersion: 1;
  manifestDigest: string;
  signedAt: string;
  proof: { algorithm: 'Ed25519'; keyId: string; proofBytes: string };
}

export interface PublisherTrust {
  kind: 'analytics-spine-pack-publisher-trust';
  schemaVersion: 1;
  keys: {
    keyId: string;
    publicKeySpki: string;
    notBefore: string;
    notAfter: string;
    state: 'active' | 'retired' | 'revoked';
  }[];
}

export type PublicKey = string | Buffer | KeyObject;
export interface ValidateOptions {
  packDir: string;
  engineVersion?: string;
  mode?: 'production' | 'test';
}
export interface VerifyOptions extends ValidateOptions {
  trust: unknown;
  now: string;
}
export interface ValidatedPack {
  manifest: Manifest;
  manifestDigest: string;
  files: PackFile[];
}
export interface VerifiedPack extends ValidatedPack {
  signature: PackSignature;
  signatureDigest: string;
}
