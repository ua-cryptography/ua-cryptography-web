/**
 * The reports of the package `ua-cryptography`, as crates/ua-cryptography-ffi/src/models/reports of ua-cryptography-rust
 * serialises them. The package's .d.ts declares them as `any`; these types stand in until it declares them.
 * Times are UTC, ISO 8601 ("2026-10-10T18:26:46Z").
 */

/** An algorithm as a signature or a certificate names it, with its readable name. */
export interface AlgorithmRow {
  /** An OID in CMS and X.509, a URI in XML-DSig. */
  identifier: string;
  /** E.g. "DSTU 7564-256"; the identifier itself when it has no name. */
  name: string;
}

/** What a certificate says. */
export interface CertificateDetails {
  /** E.g. "CN=Name, O=Organization, C=UA". */
  subject: string;
  issuer: string;
  /** Upper-case hex without leading zeros. */
  serial: string;
  valid_from: string;
  valid_to: string;
  signature_algorithm: AlgorithmRow;
  is_ca: boolean;
  ocsp_urls: string[];
  ca_issuer_urls: string[];
  time_stamp_urls: string[];
}

export type CheckOutcome = 'passed' | 'warning' | 'failed';

/** One verification step. */
export interface CheckRow {
  name: string;
  status: CheckOutcome;
  details: string;
}

/** What a signature covers: a XAdES reference, or "content" in CAdES. */
export interface ReferenceRow {
  name: string;
  digest_algorithm: AlgorithmRow;
  /** Upper-case hex. */
  digest: string;
}

/** The verification of one signature, or of an ASiC container's structure (titled "container"). */
export interface SignatureSummary {
  /** E.g. "CAdES signature". */
  title: string;
  /** E.g. "XAdES-B-LT" or "CAdES-T". */
  level: string | null;
  /** "detached" or "enveloped". */
  packaging: string | null;
  signature_algorithm: AlgorithmRow | null;
  digest_algorithm: AlgorithmRow | null;
  /** The signing time the signer claims. */
  signing_time: string | null;
  /** The time of the signature time-stamp, when present and valid. */
  timestamp_time: string | null;
  /** The time the certificates were validated at: the time-stamp, else the claimed time, else now. */
  validation_time: string | null;
  is_valid: boolean;
  has_warnings: boolean;
  signer: CertificateDetails | null;
  references: ReferenceRow[];
  /** Every check in the order made. */
  checks: CheckRow[];
}

/** The title of an ASiC container's structure report. */
export const CONTAINER_TITLE = 'container';

/** The verification of a signed file: the verdict and a summary per signature. */
export interface VerificationSummary {
  /** E.g. "ASiC-E" or "CAdES (enveloped)". */
  format: string;
  is_valid: boolean;
  /** The signatures, the container's structure report excluded. */
  signature_count: number;
  warning_count: number;
  failure_count: number;
  verified_at: string;
  /** The names of the files the signatures cover ("content" for the content of a CAdES). */
  signed_files: string[];
  /** The structure report of a container first, then each signature. */
  signatures: SignatureSummary[];
}

export type KeyStoreEntryKind = 'private_key' | 'trusted_certificate';

/** One entry of a key store. */
export interface KeyStoreEntryRow {
  alias: string;
  kind: KeyStoreEntryKind;
  created: string;
  /** The chain of a private key as stored, or the trusted certificate. */
  certificates: CertificateDetails[];
}

/** The kinds of the package's refusals: the `name` of the Error it throws. */
export type RefusalKind = 'InvalidArgument' | 'UnreadableInput' | 'WrongPassword' | 'AuthenticationFailed' | 'ServiceFailure';
