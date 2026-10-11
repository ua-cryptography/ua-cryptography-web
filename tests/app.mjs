/**
 * Drives the built page (build/index.html) in headless Chrome from a file:// URL: every synthetic signature fails as
 * untrusted, becomes valid once its signer's certificate is added on the Certificates tab and stays valid after a
 * reload; detached data is matched and a tampered document rejected; a key store opens (a wrong password is refused with
 * WrongPassword), a document is signed in every offered format and hash, and the new signature verifies. With the real
 * signatures and key on this machine (UA_PRIVATE_SAMPLES), the PrivatBank .sig and the «Дія» .asice verify against the
 * bundled roots and the bank's key signs. No exceptions, console errors or CSP violations, and no request leaves the page.
 *
 * Needs `npm run build` first and a local Chrome (or CHROME=/path/to/chrome); skipped without Chrome.
 * `--shots DIR` saves screenshots of the screens.
 */
import { existsSync, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { findChrome, launch } from '../tools/chrome.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const APP = pathToFileURL(join(root, 'build', 'index.html')).href;
const SYNTHETIC = join(root, 'tests', 'data', 'synthetic');
/** Real signatures and keys carry personal data and never enter the repository; the tests that need them skip without. */
const PRIVATE = process.env.UA_PRIVATE_SAMPLES ?? join(root, '..', 'ua-cryptography-csharp', 'private');
const shotsAt = process.argv.indexOf('--shots');
const SHOTS = shotsAt > 0 ? process.argv[shotsAt + 1] : null;

let passed = 0;
let failed = 0;
function check(name, actual, expected) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) passed++;
  else {
    failed++;
    console.error(`FAIL  ${name}\n  expected: ${b}\n  actual:   ${a}`);
  }
}

const chromePath = findChrome();
if (!chromePath) {
  console.log('app: no Chrome found — set CHROME=/path/to/chrome. Skipped.');
  process.exit(0);
}
if (!existsSync(join(root, 'build', 'index.html'))) {
  console.error('app: build/index.html is missing — run `npm run build` first.');
  process.exit(1);
}

const work = await mkdtemp(join(tmpdir(), 'ua-cryptography-web-'));
const browser = await launch(chromePath);
const { evaluate, until } = browser;
const synthetic = (name) => join(SYNTHETIC, name);
const shot = async (name, width, height) => {
  if (!SHOTS) return;
  await mkdir(SHOTS, { recursive: true });
  await writeFile(join(SHOTS, `${name}.png`), await browser.screenshot(width, height));
};
const open = async () => {
  await browser.navigate(APP);
  await until('document.documentElement.dataset.ready === "true"', 30000);
};

try {
  await browser.send('Network.enable');
  await browser.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "window.__violations = []; document.addEventListener('securitypolicyviolation', (e) => window.__violations.push(e.violatedDirective + ' ' + e.blockedURI));",
  });
  await open();
  check('the page starts', await evaluate('document.title'), 'Ukrainian e-signature — verify and sign');
  check('built-in roots: ЦЗО ×4 and НБУ', await evaluate('document.querySelectorAll("#trust-roots li").length'), 5);
  check('built-in intermediates: Дія, ПриватБанк and its bundle', await evaluate('[...document.querySelectorAll("#trust-intermediates li .who b")].map((b) => b.textContent)'), [
    '"Дія". Кваліфікований надавач електронних довірчих послуг',
    'privatbank-PB-2026-NBU.p7b',
    'КНЕДП АЦСК АТ КБ "ПриватБанк"',
  ]);
  await shot('verify-empty', 1100, 800);

  /** Verifies the files on the Verify tab; returns [verdict, the names of the failed checks]. */
  const verify = async (...files) => {
    await evaluate('document.getElementById("tab-verify").click(); document.getElementById("verify-result").replaceChildren()');
    await browser.setFiles('#verify-input', files);
    await until('document.querySelector("#verify-result .result, #verify-result .banner--fail") !== null');
    return evaluate(`(() => {
      const r = document.querySelector('#verify-result .result');
      if (!r) return ['error', document.querySelector('#verify-result').textContent];
      return [r.dataset.verdict, [...r.querySelectorAll('.signature details.all-checks .checks li.failed .name, .card:not(.signature) > .checks li.failed .name')].map((n) => n.textContent)];
    })()`);
  };

  const SIGNATURES = [
    ['cades-enveloped.p7s'],
    ['cades-gost.p7s'],
    ['cades-detached.p7s', 'document.txt'],
    ['xades-detached.xml', 'document.txt'],
    ['asic-e.asice'],
    ['asic-e-gost.asice'],
    ['asic-s.asics'],
  ];

  // ---- Synthetic signatures: not trusted until their signers' certificates are added ----
  for (const files of SIGNATURES) check(`${files[0]} is not trusted by default`, await verify(...files.map(synthetic)), ['fail', ['signer: trust']]);

  await evaluate('document.getElementById("tab-trust").click()');
  await browser.setFiles('#add-root-input', [synthetic('signer-257.cer'), synthetic('signer-431-gost.cer'), synthetic('document.txt')]);
  await until('document.querySelector("#trust-message .message") !== null');
  check('adding roots reports what happened', await evaluate('document.querySelector("#trust-message").textContent'), '2 files added as trusted roots; not certificates: document.txt.');
  check('the added roots are listed with a Remove button', await evaluate('[...document.querySelectorAll("#trust-roots li")].filter((li) => li.querySelector("button")).map((li) => li.querySelector(".who b").textContent)'), ["Тестовий підписувач", "Test Signer GOST"]);
  await shot('certificates', 1100, 900);

  // The added roots survive a reload (localStorage).
  await open();
  check('the added roots stay after a reload', await evaluate('document.querySelectorAll("#trust-roots li").length'), 7);

  for (const files of SIGNATURES) check(`${files.join(' + ')} verifies`, await verify(...files.map(synthetic)), ['ok', []]);
  await shot('verify-valid', 1100, 1100);
  check('a detached CAdES without its document fails', await verify(synthetic('cades-detached.p7s')), ['fail', ['content']]);
  const tampered = join(work, 'document.txt');
  await writeFile(tampered, (await readFile(synthetic('document.txt'), 'utf8')).replace('Тестовий', 'Змінений'));
  check('a tampered document is rejected (XAdES)', await verify(synthetic('xades-detached.xml'), tampered), ['fail', ["reference 'document.txt'"]]);
  check('a tampered document is rejected (CAdES)', (await verify(synthetic('cades-detached.p7s'), tampered))[0], 'fail');
  await shot('verify-invalid', 1100, 1000);
  const junk = join(work, 'junk.sig');
  await writeFile(junk, 'not a signature');
  const [junkVerdict, junkText] = await verify(junk);
  check('junk is reported as a refusal, not thrown', [junkVerdict, /The file could not be read as a signatureUnreadableInput: /.test(junkText)], ['error', true]);

  // ---- Signing with the synthetic keys ----
  await evaluate('document.getElementById("tab-sign").click()');
  check('Sign is disabled without a key', await evaluate('document.getElementById("sign-run").disabled'), true);
  await browser.setFiles('#key-file', [synthetic('signer-257.jks')]);
  await evaluate('document.getElementById("key-password").value = "wrong"; document.getElementById("key-open").click()');
  await until('document.querySelector("#key-info .banner--fail") !== null');
  check('a wrong password is refused with WrongPassword', await evaluate('[document.querySelector("#key-info strong").textContent, document.querySelector("#key-info p").textContent.split(":")[0]]'), ['Wrong password', 'WrongPassword']);

  /** Opens a synthetic key store with the right password. */
  const openKey = async (store) => {
    if (await evaluate('document.getElementById("key-form").hidden')) await evaluate('document.querySelector("#key-info .link").click()');
    await browser.setFiles('#key-file', [store]);
    await evaluate('document.getElementById("key-password").value = "synthetic test password"; document.getElementById("key-open").click()');
    await until('document.querySelector("#key-info .banner--ok, #key-info .banner--fail") !== null');
  };
  /** Signs the chosen document; returns [verdict, the format row, the Save button]. */
  const signAs = async (format, hash) => {
    await evaluate(`document.getElementById("sign-format").value = "${format}"; document.getElementById("sign-hash").value = "${hash}"; document.getElementById("sign-result").replaceChildren(); document.getElementById("sign-run").click()`);
    await until('document.querySelector("#sign-result .result, #sign-result .banner--fail") !== null', 30000);
    return evaluate('[document.querySelector("#sign-result .result")?.dataset.verdict ?? document.querySelector("#sign-result").textContent, document.querySelector("#sign-result .signature .facts dd")?.textContent, document.getElementById("sign-save")?.textContent]');
  };

  await openKey(synthetic('signer-257.jks'));
  check('the key opens and shows its owner', await evaluate('document.querySelector("#key-info strong").textContent'), 'Тестовий підписувач');
  check('one key: no alias to choose', await evaluate('document.getElementById("key-alias-field").hidden'), true);
  check('the password field is cleared', await evaluate('document.getElementById("key-password").value'), '');
  await browser.setFiles('#sign-input', [synthetic('document.txt')]);
  await until('!document.getElementById("sign-run").disabled');
  const FORMATS = [
    ['cades-enveloped', 'CAdES-B, enveloped', 'sig'],
    ['cades-detached', 'CAdES-B, detached', 'p7s'],
    ['asic-e', 'XAdES-B-B, detached', 'asice'],
  ];
  const HASHES = [
    ['dstu7564', 'DSTU 7564-256'],
    ['gost34311', 'GOST 34.311-95'],
  ];
  for (const [format, title, extension] of FORMATS) {
    for (const [hash, hashName] of HASHES) {
      check(`signed as ${format} with ${hash}, verified on the spot`, await signAs(format, hash), ['ok', `${title}, ${hashName}`, `Save document.txt.${extension}`]);
    }
  }
  await signAs('cades-enveloped', 'dstu7564');
  await shot('sign', 1100, 1200);

  await openKey(synthetic('signer-431-gost.jks'));
  check('the m = 431 key signs too', await signAs('asic-e', 'gost34311'), ['ok', 'XAdES-B-B, detached, GOST 34.311-95', 'Save document.txt.asice']);

  // ---- Real signatures and key (never in the repository) ----
  if (!existsSync(PRIVATE)) {
    console.log('app: no real signatures on this machine — skipped');
  } else {
    // The same verdicts as the reference page (ua-cryptography-typescript) and `ua-sign verify`: valid, with warnings
    // only for the revocation status that cannot be checked offline.
    check('PrivatBank .sig: valid, warnings only', await verify(join(PRIVATE, 'pb', 'valid', 'tosign.txt.sig')), ['warn', []]);
    check('PrivatBank .sig: the time-stamp is verified', await evaluate('[...document.querySelectorAll("#verify-result .facts dt")].some((dt) => dt.textContent === "Time-stamp")'), true);
    await shot('verify-privatbank', 1100, 1300);
    check('«Дія» .asice: valid, warnings only', await verify(join(PRIVATE, 'ASIC-E', 'tosign.txt.asice')), ['warn', []]);
    await shot('verify-diia', 1100, 1300);

    const passwordFile = process.env.UA_PRIVATE_JKS_PASSWORD_FILE ?? join(PRIVATE, 'pb', 'temp.txt');
    const store = readdirSync(join(PRIVATE, 'pb')).find((n) => n.endsWith('.jks'));
    if (store && existsSync(passwordFile)) {
      const password = (await readFile(passwordFile, 'utf8')).trim();
      await evaluate('document.getElementById("tab-sign").click(); document.querySelector("#key-info .link").click()');
      await browser.setFiles('#key-file', [join(PRIVATE, 'pb', store)]);
      await evaluate(`document.getElementById("key-password").value = ${JSON.stringify(password)}; document.getElementById("key-open").click()`);
      await until('document.querySelector("#key-info .banner--ok, #key-info .banner--fail") !== null');
      check('PrivatBank key: opens', await evaluate('document.querySelector("#key-info .banner--ok") !== null'), true);
      const [verdict, format] = await signAs('cades-enveloped', 'dstu7564');
      check('PrivatBank key: CAdES-B verifies up to the NBU root', [verdict, format, await evaluate('document.querySelectorAll("#sign-result li.failed").length')], ['warn', 'CAdES-B, enveloped, DSTU 7564-256', 0]);
    }
  }

  // ---- Phone width ----
  await evaluate('document.getElementById("tab-verify").click()');
  await shot('phone', 390, 844);
  if (SHOTS) check('no horizontal scroll at the phone width', await evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1'), true);

  check('no page errors', browser.errors, []);
  check('no CSP violations', await evaluate('window.__violations'), []);
  const requests = browser.events.filter((e) => e.method === 'Network.requestWillBeSent').map((e) => e.params.request.url);
  check('no request leaves the page', requests.filter((url) => !/^(file|data|blob):/.test(url)), []);
  // The policy blocks any request the page might try.
  check('any address is blocked', await evaluate('fetch("https://example.com/").then(() => "reached", () => "blocked")'), 'blocked');
  check('…by connect-src', await evaluate('window.__violations'), ['connect-src https://example.com/']);
} finally {
  await browser.close();
  await rm(work, { recursive: true, force: true });
}

console.log(`app: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
