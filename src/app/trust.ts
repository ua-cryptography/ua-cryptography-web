import { INTERMEDIATES, ROOTS } from 'bundled-certificates';
import type { CertificateDetails } from '../reports';
import { certificateDetails, verifySignature } from './package';

export type Role = 'root' | 'intermediate';

/**
 * A certificate file as the user or the build gave it: DER, PEM or a .p7b bundle, passed to the package as it is.
 * `details` is null for a bundle: the package describes one certificate at a time and cannot list a bundle's.
 */
export type TrustEntry = {
  readonly name: string;
  readonly bytes: Uint8Array;
  readonly base64: string;
  readonly role: Role;
  readonly builtIn: boolean;
  readonly details: CertificateDetails | null;
};

const STORAGE_KEY = 'ua-cryptography-web.certificates';

/**
 * The certificates verification relies on: the files built into the page (assets/certificates) and those the user
 * added, kept in localStorage as { name, role, base64 } — public certificates, nothing secret.
 */
export class TrustStore {
  private readonly entries: TrustEntry[] = [];
  private readonly listeners: Array<() => void> = [];

  constructor() {
    for (const { name, base64 } of ROOTS) this.push(name, base64, 'root', true);
    for (const { name, base64 } of INTERMEDIATES) this.push(name, base64, 'intermediate', true);
    for (const stored of readStored()) {
      try {
        this.push(stored.name, stored.base64, stored.role, false);
      } catch {
        // A damaged stored entry is dropped at the next save.
      }
    }
  }

  get all(): readonly TrustEntry[] {
    return this.entries;
  }

  onChange(listener: () => void): void {
    this.listeners.push(listener);
  }

  get trustAnchors(): Uint8Array[] {
    return this.entries.filter((e) => e.role === 'root').map((e) => e.bytes);
  }

  get certificates(): Uint8Array[] {
    return this.entries.filter((e) => e.role === 'intermediate').map((e) => e.bytes);
  }

  /**
   * Adds certificate files with a role; returns how many were new and the names of the files the package cannot read.
   * A known file keeps its place (or becomes a root).
   */
  add(files: ReadonlyArray<{ name: string; bytes: Uint8Array }>, role: Role): { added: number; known: number; failed: string[] } {
    let added = 0;
    let known = 0;
    const failed: string[] = [];
    for (const { name, bytes } of files) {
      if (!isReadable(bytes)) {
        failed.push(name);
        continue;
      }
      const base64 = toBase64(bytes);
      const existing = this.entries.findIndex((e) => e.base64 === base64);
      if (existing < 0) {
        this.push(name, base64, role, false);
        added++;
      } else if (role === 'root' && this.entries[existing]!.role !== 'root') {
        this.entries[existing] = { ...this.entries[existing]!, role: 'root', builtIn: false };
        added++;
      } else {
        known++;
      }
    }
    if (added > 0) this.save();
    return { added, known, failed };
  }

  remove(entry: TrustEntry): void {
    const i = this.entries.indexOf(entry);
    if (i >= 0 && !entry.builtIn) {
      this.entries.splice(i, 1);
      this.save();
    }
  }

  private push(name: string, base64: string, role: Role, builtIn: boolean): void {
    if (this.entries.some((e) => e.base64 === base64)) return;
    const bytes = fromBase64(base64);
    this.entries.push({ name, bytes, base64, role, builtIn, details: describe(bytes) });
  }

  private save(): void {
    const stored = this.entries.filter((e) => !e.builtIn).map((e) => ({ name: e.name, role: e.role, base64: e.base64 }));
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    } catch {
      // Storage may be unavailable (a private window, a file:// policy): the certificates stay for this session.
    }
    for (const listener of this.listeners) listener();
  }
}

function describe(bytes: Uint8Array): CertificateDetails | null {
  try {
    return certificateDetails(bytes);
  } catch {
    return null;
  }
}

/**
 * Whether the package reads the file as certificates. One certificate is described; a bundle cannot be, so it is handed
 * to `verify` as a certificate (with itself as the signature): the package parses every certificate input first and
 * refuses an unreadable one, which would otherwise break every later verification.
 */
function isReadable(bytes: Uint8Array): boolean {
  if (describe(bytes)) return true;
  try {
    verifySignature(bytes, [], [], [bytes]);
    return true;
  } catch {
    return false;
  }
}

function readStored(): Array<{ name: string; role: Role; base64: string }> {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    if (!Array.isArray(value)) return [];
    return value.filter(
      (v): v is { name: string; role: Role; base64: string } =>
        typeof v === 'object' && v !== null && (v.role === 'root' || v.role === 'intermediate') && typeof v.base64 === 'string' && typeof v.name === 'string',
    );
  } catch {
    return [];
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function fromBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
