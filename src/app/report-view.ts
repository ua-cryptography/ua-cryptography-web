import { type CertificateDetails, type CheckOutcome, type CheckRow, CONTAINER_TITLE, type SignatureSummary, type VerificationSummary } from '../reports';
import { commonName, formatDay, formatTime, h, nameParts } from './ui';

/** The verdict of a whole report: 'ok', 'warn' (valid, something not established) or 'fail'. */
export function verdict(summary: VerificationSummary): 'ok' | 'warn' | 'fail' {
  if (!summary.is_valid) return 'fail';
  return summary.signatures.some((s) => s.has_warnings) ? 'warn' : 'ok';
}

const MARK: Record<CheckOutcome, string> = { passed: '✓', warning: '!', failed: '✗' };

function checkList(checks: readonly CheckRow[]): HTMLUListElement {
  return h(
    'ul',
    { class: 'checks' },
    ...checks.map((c) => h('li', { class: c.status }, h('span', { class: 'mark', 'aria-label': c.status }, MARK[c.status]), h('div', null, h('span', { class: 'name' }, c.name), ': ', h('span', { class: 'details' }, c.details)))),
  );
}

function certificateFacts(c: CertificateDetails): Array<[string, string]> {
  const subject = nameParts(c.subject);
  const facts: Array<[string, string]> = [];
  const organization = subject.get('O');
  const identifier = subject.get('SERIALNUMBER');
  if (organization) facts.push(['Organization', organization]);
  if (identifier) facts.push(['Identifier', identifier]);
  facts.push(['Issued by', commonName(c.issuer)]);
  facts.push(['Certificate valid', `${formatDay(c.valid_from)} – ${formatDay(c.valid_to)}`]);
  return facts;
}

function facts(rows: Array<[string, string]>): HTMLDListElement {
  return h('dl', { class: 'facts' }, ...rows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
}

/** "CAdES-B, enveloped, DSTU 7564-256". */
function formatOf(s: SignatureSummary): string {
  return [s.level, s.packaging, s.digest_algorithm?.name].filter(Boolean).join(', ');
}

function signatureCard(s: SignatureSummary): HTMLElement {
  const status = !s.is_valid ? 'fail' : s.has_warnings ? 'warn' : 'ok';
  const label = status === 'fail' ? 'INVALID' : status === 'warn' ? 'VALID, WITH WARNINGS' : 'VALID';
  const card = h('div', { class: 'card signature' });
  card.append(h('div', { class: 'signature-head' }, h('h3', null, s.signer ? commonName(s.signer.subject) : s.title), h('span', { class: `pill pill--${status}` }, label)));

  const rows: Array<[string, string]> = [];
  const format = formatOf(s);
  if (format) rows.push(['Format', format]);
  if (s.signature_algorithm) rows.push(['Algorithm', s.signature_algorithm.name]);
  if (s.signing_time) rows.push(['Signed at', `${formatTime(s.signing_time)} (as the signer's computer says)`]);
  if (s.timestamp_time) rows.push(['Time-stamp', `${formatTime(s.timestamp_time)} (qualified time-stamp, verified)`]);
  if (s.signer) rows.push(...certificateFacts(s.signer));
  if (s.validation_time) rows.push(['Validated at', formatTime(s.validation_time)]);
  rows.push(['Signature', s.title]);
  card.append(facts(rows));

  const problems = s.checks.filter((c) => c.status !== 'passed');
  if (problems.length > 0) card.append(h('p', { class: 'section-title' }, 'Attention'), checkList(problems));
  card.append(h('details', { class: 'all-checks' }, h('summary', null, `All checks (${s.checks.length})`), checkList(s.checks)));
  if (s.references.length > 0) {
    card.append(h('details', { class: 'all-checks' }, h('summary', null, 'Signed digests'), facts(s.references.map((r) => [r.name, `${r.digest_algorithm.name} ${r.digest.toLowerCase()}`]))));
  }
  return card;
}

/**
 * The banner, the container's checks, one card per signature and, unless `withContent` is false (a signature just made
 * of a known document), the names of the signed files.
 */
export function renderResult(summary: VerificationSummary, fileName: string, withContent = true): HTMLElement {
  const v = verdict(summary);
  const signatures = summary.signatures.filter((s) => s.title !== CONTAINER_TITLE);
  const container = summary.signatures.find((s) => s.title === CONTAINER_TITLE);
  const headline = v === 'fail' ? 'The signature is NOT valid' : 'The signature is valid';
  const explanation =
    v === 'fail'
      ? 'At least one check failed — see the marked items below.'
      : v === 'warn'
        ? 'Some things could not be established offline (usually the current revocation status); see "Attention".'
        : 'Every check passed.';
  const root = h('div', { class: 'result' });
  root.dataset.verdict = v;
  root.append(
    h(
      'div',
      { class: `banner banner--${v}` },
      h('span', { class: 'icon' }, v === 'fail' ? '✗' : '✓'),
      h(
        'div',
        null,
        h('strong', null, headline),
        h('p', null, explanation),
        h('p', { class: 'file' }, `${fileName} — ${summary.format}, ${signatures.length} signature${signatures.length === 1 ? '' : 's'} · verified at ${formatTime(summary.verified_at)}`),
      ),
    ),
  );
  if (container && container.checks.some((c) => c.status !== 'passed')) {
    root.append(h('div', { class: 'card' }, h('h3', null, 'Container'), checkList(container.checks)));
  }
  for (const s of signatures) root.append(signatureCard(s));

  if (withContent && summary.signed_files.length > 0) {
    root.append(
      h(
        'div',
        { class: 'card' },
        h('h3', null, 'Signed content'),
        h('ul', { class: 'signed-files' }, ...summary.signed_files.map((name) => h('li', null, h('code', null, name)))),
        h('p', { class: 'hint' }, 'Saving the signed document from the signature is not available yet: the library reports the names of the signed files, not their content.'),
      ),
    );
  }
  return root;
}

export function busy(text: string): HTMLElement {
  return h('div', { class: 'banner banner--busy' }, h('span', { class: 'icon' }, '…'), h('div', null, h('strong', null, text)));
}

export function failure(title: string, message: string): HTMLElement {
  return h('div', { class: 'banner banner--fail' }, h('span', { class: 'icon' }, '✗'), h('div', null, h('strong', null, title), h('p', null, message)));
}
