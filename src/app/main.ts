import type { KeyStoreEntryRow } from '../reports';
import { keyStoreEntries, load, type NamedBytes, refusalKind, sign, SignatureFormat, SignatureHash, SignatureLevel, verifySignature } from './package';
import { busy, failure, renderResult } from './report-view';
import { TrustStore, type TrustEntry, type Role } from './trust';
import { byId, commonName, download, errorText, fileDrop, formatDay, h, nameParts, nextFrame, readFile } from './ui';

// ---- Tabs ------------------------------------------------------------------------------------------------------------

const VIEWS = ['verify', 'sign', 'trust'] as const;
type View = (typeof VIEWS)[number];

function show(view: View): void {
  for (const v of VIEWS) {
    byId(`view-${v}`).hidden = v !== view;
    byId(`tab-${v}`).setAttribute('aria-selected', String(v === view));
  }
}
for (const v of VIEWS) byId(`tab-${v}`).addEventListener('click', () => show(v));

// A file dropped outside a drop zone must not make the browser open it instead of the page.
window.addEventListener('dragover', (event) => event.preventDefault());
window.addEventListener('drop', (event) => event.preventDefault());

/** A refusal of the package as "WrongPassword: …", any other error as its message. */
function refusalText(error: unknown): string {
  const kind = refusalKind(error);
  return kind ? `${kind}: ${errorText(error)}` : errorText(error);
}

async function start(): Promise<void> {
  await load();
  const trust = new TrustStore();

  // ---- Verify --------------------------------------------------------------------------------------------------------

  const SIGNATURE_EXTENSIONS = /\.(sig|p7s|p7m|asice|sce|asics|scs|xml)$/i;
  const verifyResult = byId('verify-result');

  /** The signature among the dropped files — by its extension, else the only file — and the rest as signed data. */
  function splitFiles(files: NamedBytes[]): { signature: NamedBytes; data: NamedBytes[] } | null {
    const signature = files.length === 1 ? files[0]! : files.find((f) => SIGNATURE_EXTENSIONS.test(f.name));
    return signature ? { signature, data: files.filter((f) => f !== signature) } : null;
  }

  async function verifyFiles(files: File[]): Promise<void> {
    verifyResult.replaceChildren(busy('Verifying…'));
    await nextFrame();
    try {
      const split = splitFiles(await Promise.all(files.map(async (f) => ({ name: f.name, content: await readFile(f) }))));
      if (!split) {
        verifyResult.replaceChildren(failure('Which file is the signature?', 'Drop one signature (.sig, .p7s, .asice, .asics, .xml) and, for a detached signature, the signed file.'));
        return;
      }
      const started = performance.now();
      const summary = verifySignature(split.signature.content, split.data, trust.trustAnchors, trust.certificates);
      const view = renderResult(summary, split.signature.name);
      view.dataset.ms = String(Math.round(performance.now() - started));
      verifyResult.replaceChildren(view);
    } catch (error) {
      verifyResult.replaceChildren(failure('The file could not be read as a signature', refusalText(error)));
    }
  }

  fileDrop(byId('verify-drop'), byId<HTMLInputElement>('verify-input'), byId('verify-pick'), (files) => void verifyFiles(files));

  // ---- Sign ----------------------------------------------------------------------------------------------------------

  /** The open key store: kept in memory, with its password, only while the page is open. */
  let key: { fileName: string; keyStore: Uint8Array; password: string; entries: KeyStoreEntryRow[] } | null = null;
  let document_: NamedBytes | null = null;
  const keyInfo = byId('key-info');
  const keyAlias = byId<HTMLSelectElement>('key-alias');
  const signRun = byId<HTMLButtonElement>('sign-run');
  const signResult = byId('sign-result');

  function updateSignButton(): void {
    signRun.disabled = !(key && document_);
    byId('sign-card').classList.toggle('disabled', !key);
  }

  function closeKey(): void {
    key = null;
    keyInfo.hidden = true;
    keyInfo.replaceChildren();
    byId('key-alias-field').hidden = true;
    byId('key-form').hidden = false;
    updateSignButton();
  }

  /** The owner and the chain of the chosen private key. */
  function renderKey(): void {
    if (!key) return;
    const entry = key.entries.find((e) => e.alias === keyAlias.value);
    const certificate = entry?.certificates[0];
    if (!entry || !certificate) return;
    const subject = nameParts(certificate.subject);
    keyInfo.replaceChildren(
      h(
        'div',
        { class: 'banner banner--ok' },
        h('span', { class: 'icon' }, '🔑'),
        h(
          'div',
          null,
          h('strong', null, commonName(certificate.subject)),
          h('p', null, [subject.get('SERIALNUMBER'), `issued by ${commonName(certificate.issuer)}`, `valid ${formatDay(certificate.valid_from)} – ${formatDay(certificate.valid_to)}`].filter(Boolean).join(' · ')),
          h('p', { class: 'file' }, `${key.fileName} · key "${entry.alias}" · ${certificate.signature_algorithm.name} · chain: ${entry.certificates.map((c) => commonName(c.subject)).join(' → ')}`),
          h('p', null, h('button', { type: 'button', class: 'link', onclick: closeKey }, 'Close the key')),
        ),
      ),
    );
    if (new Date() > new Date(certificate.valid_to)) keyInfo.append(failure('The certificate has expired', `It was valid until ${formatDay(certificate.valid_to)}; a signature made now will not verify.`));
  }

  byId<HTMLFormElement>('key-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void (async () => {
      const fileInput = byId<HTMLInputElement>('key-file');
      const passwordInput = byId<HTMLInputElement>('key-password');
      const file = fileInput.files?.[0];
      keyInfo.hidden = false;
      if (!file) {
        keyInfo.replaceChildren(failure('No key store', 'Choose the .jks file the provider issued.'));
        return;
      }
      keyInfo.replaceChildren(busy('Opening the key…'));
      await nextFrame();
      try {
        const keyStore = await readFile(file);
        const password = passwordInput.value;
        const entries = keyStoreEntries(keyStore, password).filter((e) => e.kind === 'private_key' && e.certificates.length > 0);
        if (entries.length === 0) throw new Error('The key store holds no private key with a certificate.');
        key = { fileName: file.name, keyStore, password, entries };
        passwordInput.value = '';
        fileInput.value = '';
        keyAlias.replaceChildren(...entries.map((e) => h('option', { value: e.alias }, `${e.alias} — ${commonName(e.certificates[0]!.subject)}`)));
        byId('key-alias-field').hidden = entries.length < 2;
        byId('key-form').hidden = true;
        renderKey();
      } catch (error) {
        key = null;
        const wrong = refusalKind(error) === 'WrongPassword';
        keyInfo.replaceChildren(failure(wrong ? 'Wrong password' : 'The key could not be opened', refusalText(error)));
      }
      updateSignButton();
    })();
  });
  keyAlias.addEventListener('change', renderKey);

  fileDrop(byId('sign-drop'), byId<HTMLInputElement>('sign-input'), byId('sign-pick'), (files) => {
    void (async () => {
      const file = files[0]!;
      document_ = { name: file.name, content: await readFile(file) };
      byId('sign-file-name').textContent = `${file.name} (${document_.content.length.toLocaleString('en')} bytes)`;
      signResult.replaceChildren();
      updateSignButton();
    })();
  });

  /** The formats offered: [package format, detached, extension, media type]. */
  const FORMATS: Record<string, [SignatureFormat, boolean, string, string]> = {
    'cades-enveloped': [SignatureFormat.Cades, false, 'sig', 'application/pkcs7-signature'],
    'cades-detached': [SignatureFormat.Cades, true, 'p7s', 'application/pkcs7-signature'],
    'asic-e': [SignatureFormat.AsicE, false, 'asice', 'application/vnd.etsi.asic-e+zip'],
  };

  signRun.addEventListener('click', () => {
    void (async () => {
      if (!key || !document_) return;
      signResult.replaceChildren(busy('Signing…'));
      await nextFrame();
      try {
        const [format, detached, extension, type] = FORMATS[byId<HTMLSelectElement>('sign-format').value]!;
        const hash = byId<HTMLSelectElement>('sign-hash').value === 'gost34311' ? SignatureHash.Gost34311 : SignatureHash.Dstu7564;
        const signature = sign(key.keyStore, key.password, keyAlias.value, [document_], format, SignatureLevel.B, hash, detached, []);
        const name = `${document_.name}.${extension}`;
        const view = renderResult(verifySignature(signature, detached ? [document_] : [], trust.trustAnchors, trust.certificates), name, false);
        signResult.replaceChildren(
          h(
            'div',
            { class: 'banner banner--ok' },
            h('span', { class: 'icon' }, '✓'),
            h(
              'div',
              null,
              h('strong', null, `Signed: ${name}`),
              h('p', null, `${signature.length.toLocaleString('en')} bytes. Below is the verification of the new signature.`),
              h('p', null, h('button', { type: 'button', class: 'button button--primary', id: 'sign-save', onclick: () => download(name, signature, type) }, `Save ${name}`)),
            ),
          ),
          view,
        );
      } catch (error) {
        signResult.replaceChildren(failure('Signing failed', refusalText(error)));
      }
    })();
  });
  updateSignButton();

  // ---- Certificates --------------------------------------------------------------------------------------------------

  function renderTrust(): void {
    const item = (entry: TrustEntry): HTMLLIElement => {
      const c = entry.details;
      const about = c
        ? [nameParts(c.subject).get('SERIALNUMBER'), `valid ${formatDay(c.valid_from)} – ${formatDay(c.valid_to)}`, c.subject === c.issuer ? 'self-signed' : `issued by ${commonName(c.issuer)}`]
        : ['a certificate bundle (.p7b), passed to the library as it is'];
      return h(
        'li',
        null,
        h('div', { class: 'who' }, h('b', null, c ? commonName(c.subject) : entry.name), h('span', null, [...about, entry.name].filter(Boolean).join(' · '))),
        entry.builtIn ? h('span', { class: 'badge' }, 'built in') : h('button', { type: 'button', class: 'button button--small', onclick: () => trust.remove(entry) }, 'Remove'),
      );
    };
    byId('trust-roots').replaceChildren(...trust.all.filter((e) => e.role === 'root').map(item));
    const intermediates = trust.all.filter((e) => e.role === 'intermediate');
    byId('trust-intermediates').replaceChildren(...intermediates.map(item));
    byId('trust-intermediates-count').textContent = `Show all ${intermediates.length}`;
  }

  async function addCertificates(files: File[], role: Role): Promise<void> {
    const result = trust.add(await Promise.all(files.map(async (f) => ({ name: f.name, bytes: await readFile(f) }))), role);
    const parts = [`${result.added} file${result.added === 1 ? '' : 's'} added as ${role === 'root' ? 'trusted roots' : 'intermediates'}`];
    if (result.known > 0) parts.push(`${result.known} already known`);
    if (result.failed.length > 0) parts.push(`not certificates: ${result.failed.join(', ')}`);
    byId('trust-message').replaceChildren(h('p', { class: `message message--${result.failed.length > 0 && result.added === 0 ? 'fail' : 'ok'}` }, `${parts.join('; ')}.`));
  }

  trust.onChange(renderTrust);
  renderTrust();
  fileDrop(byId('add-root'), byId<HTMLInputElement>('add-root-input'), byId('add-root-pick'), (files) => void addCertificates(files, 'root'));
  fileDrop(byId('add-intermediate'), byId<HTMLInputElement>('add-intermediate-input'), byId('add-intermediate-pick'), (files) => void addCertificates(files, 'intermediate'));

  document.documentElement.dataset.ready = 'true';
}

start().catch((error: unknown) => {
  byId('verify-result').replaceChildren(failure('The page could not start', errorText(error)));
  throw error;
});

