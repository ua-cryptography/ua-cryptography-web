/**
 * The package `ua-cryptography` with its WebAssembly inlined into the bundle (esbuild's binary loader), so the page
 * fetches nothing; and its untyped functions with the report types of src/reports.ts. Every cryptographic operation of
 * the page goes through here.
 */
import init, { getCertificateDetails, getKeyStoreEntries, type NamedBytes, sign, verify } from 'ua-cryptography';
import wasm from 'ua-cryptography/ua_cryptography_bg.wasm';
import type { CertificateDetails, KeyStoreEntryRow, RefusalKind, VerificationSummary } from '../reports';

export { sign, SignatureFormat, SignatureHash, SignatureLevel, type NamedBytes } from 'ua-cryptography';

/** Compiles the WebAssembly asynchronously: Chrome refuses to compile a module this large on the main thread at once. */
export async function load(): Promise<void> {
  await init({ module_or_path: wasm });
}

export function verifySignature(signature: Uint8Array, data: NamedBytes[], trustAnchors: Uint8Array[], certificates: Uint8Array[]): VerificationSummary {
  return verify(signature, data, trustAnchors, certificates) as VerificationSummary;
}

export function keyStoreEntries(keyStore: Uint8Array, password: string): KeyStoreEntryRow[] {
  return getKeyStoreEntries(keyStore, password) as KeyStoreEntryRow[];
}

/** A certificate as DER, PEM or base64 (the first one of a PEM file); a .p7b bundle is refused. */
export function certificateDetails(certificate: Uint8Array): CertificateDetails {
  return getCertificateDetails(certificate) as CertificateDetails;
}

/** The kind of a refusal of the package, or null for any other error. */
export function refusalKind(error: unknown): RefusalKind | null {
  const kinds: readonly string[] = ['InvalidArgument', 'UnreadableInput', 'WrongPassword', 'AuthenticationFailed', 'ServiceFailure'];
  return error instanceof Error && kinds.includes(error.name) ? (error.name as RefusalKind) : null;
}
