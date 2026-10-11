# UA e-signature in the browser, on WebAssembly

**Live page: <https://ua-cryptography.github.io/ua-cryptography-web/>**

Verification of Ukrainian qualified electronic signatures, and signing with a JKS key, in a static web page that works
offline. The same page as [ua-cryptography-typescript](https://github.com/ua-cryptography/ua-cryptography-typescript),
but with **no cryptography written in JavaScript**: every hash, signature, certificate, CMS, XAdES and ASiC operation
is a call into the npm package [`ua-cryptography`](https://www.npmjs.com/package/ua-cryptography), the WebAssembly
build of [ua-cryptography-rust](https://github.com/ua-cryptography/ua-cryptography-rust). The TypeScript here is UI
only — reading files, calling the package, rendering its reports, saving results — and the page is the example of
using that package in a browser.

| Format | File | Made by | Here |
|---|---|---|---|
| CAdES-T, data inside | `.sig` | PrivatBank | verified |
| ASiC-E with a detached XAdES-B-LT | `.asice` | «Дія.Підпис» | verified |
| CAdES-B, data inside or detached | `.sig`, `.p7s` | this page | signed and verified |
| ASiC-E with XAdES-B-B | `.asice` | this page | signed and verified |

Whatever else the package verifies is verified too: CAdES enveloped or detached, ASiC-S, XAdES as a separate `.xml`,
with DSTU 7564-256 or GOST 34.311 and DSTU 4145 keys.

## Using the page

Open the live page, or build it: `./build.sh` (Node.js 22 or later; it installs the dependencies on the first run,
`./build.sh --watch` rebuilds on every change) writes `build/` — `index.html`, `app.js`, `styles.css`, `icon.svg`.
Open `build/index.html` in a browser; a `file://` URL is fine.

- **Verify** — drop a signed file; for a detached signature drop the signed document together with it. The page shows
  the signer, the signing and time-stamp times, the time of the verification, every check made, and the names of the
  signed files.
- **Sign** — open a `.jks` key store with its password; with several private keys inside, choose one. Drop a document,
  choose the format — CAdES with the document inside (`<document>.sig`, as PrivatBank makes it, the default), detached
  CAdES (`.p7s`) or ASiC-E with XAdES (`.asice`, as «Дія.Підпис» makes it) — and the hash (DSTU 7564-256 by default, or
  GOST 34.311). The signature is verified on the spot and offered for saving. The key store and its password stay in
  the page's memory only while it is open.
- **Certificates** — the trusted roots and intermediate certificates verification relies on. Drop more (DER, PEM or a
  `.p7b` bundle) to add them; the files are handed to the package as they are and kept in the browser's local storage.

Built in (`assets/certificates`, all public): the ЦЗО roots (2027, 2030, 2035 with GOST 34.311; 2036 with DSTU 7564)
and the NBU root of 2036 as trusted roots; the «Дія» CA, the PrivatBank CA, and the bundle PrivatBank publishes at its
certificates' caIssuers address (`PB-2026-NBU.p7b`: its CAs, TSP and OCSP servers) as intermediates. A PrivatBank
`.sig` carries neither its CA's certificate nor the TSP server's; without the bundle the time-stamp cannot be checked.

## Network: none

The page makes no network requests. Its Content-Security-Policy has `connect-src 'none'` (the build refuses any other
value), scripts and styles come only from the page's own files, and `'wasm-unsafe-eval'` lets the browser compile the
WebAssembly, which is inlined into `app.js` — so nothing is fetched even for it, and the page works from disk.

- **Signing is at level B**, without a qualified time-stamp: the WebAssembly build reaches no network and refuses
  levels T and LT. A PrivatBank `.sig` is CAdES-T; a signature made here is CAdES-B.
- **The current revocation status is not checked.** OCSP responses embedded in a signature are verified; a certificate
  without one gets a warning. A PrivatBank `.sig` has no revocation data at all; a «Дія» `.asice` has the status of the
  signer's certificate at signing time.
- **Missing CA certificates are not downloaded**; add them on the Certificates tab.
- **"Now"** — the time a signature without a time-stamp is validated at — is the browser's clock.

## Gaps of the package

Each is a change of ua-cryptography-rust, to be proposed and made there; this page does not reimplement CMS or ASN.1 in
JavaScript to get around it.

1. **CAdES-T at signing.** A two-step API would let the page make the time-stamp request itself: `beginSign` returns
   the RFC 3161 request (or the hash of the signature value), the page fetches the token from the provider's TSP server
   (the one network exception the policy would then allow), `endSign(token)` returns the CAdES-T. Until then, level B.
2. **The signed document.** The reports name the signed files (`signed_files`) but do not carry their content, so the
   page cannot offer the document of an enveloped `.sig` or of an ASiC for saving. Needs a function such as
   `getSignedContent(signature): NamedBytes[]`.
3. **Typed reports.** `verify`, `getKeyStoreEntries` and `getCertificateDetails` return `any` in the `.d.ts`; their
   types are declared here, in `src/reports.ts`, after the models of `crates/ua-cryptography-ffi/src/models/reports`.
4. **Certificate bundles.** `getCertificateDetails` describes one certificate; a `.p7b` bundle can be neither listed nor
   checked before use. The Certificates tab shows a bundle as one file, and checks that the package reads it by handing
   it to `verify` as a certificate. Needs a function such as `getCertificates(bundle): Uint8Array[]`.

## How it is checked

`npm run check` = typecheck → build → `tests/app.mjs`, the built page in headless Chrome from a `file://` URL
(`tools/chrome.mjs`, the DevTools protocol with nothing but Node; `--shots DIR` saves screenshots):

- every synthetic signature (`tests/data/synthetic`, made by `ua-sign` of the C# reference with synthetic keys) —
  CAdES enveloped and detached, DSTU 7564 and GOST 34.311, XAdES, ASiC-E, ASiC-S — fails as untrusted, becomes valid
  after its signer's certificate is added on the Certificates tab, and stays valid after a reload;
- a detached signature is matched with its document, a missing or tampered document is rejected, junk is reported;
- a synthetic key store opens, a wrong password is refused with `WrongPassword`, a document is signed in each format
  with each hash and the new signature verifies on the spot;
- no exception, console error or CSP violation, no request leaves the page, and a `fetch` is blocked by `connect-src`.

Real signatures and keys carry personal data and are never committed. When a machine has them (`UA_PRIVATE_SAMPLES`, by
default `../ua-cryptography-csharp/private`), the test also verifies the real PrivatBank `.sig` and «Дія» `.asice`
against the bundled roots — valid, with warnings only for the revocation status, the same verdict as the reference page
and `ua-sign verify` — and signs with the bank's key.

GitHub Actions (`.github/workflows/ci.yml`) runs `npm run check` on every push and pull request and publishes `build/`
on GitHub Pages from `main`.

## Layout

```text
build.sh, build.mjs       installs the dependencies on the first run; esbuild → build/ (the WebAssembly and the
                          certificates inlined into app.js), the policy checked
src/reports.ts            the types of the package's reports
src/app/                  the page: template, styles, views; package.ts — the package, loaded and typed
assets/                   the icon and the bundled public certificates
tests/app.mjs             the built page in headless Chrome; tests/data/synthetic — its fixtures
tools/chrome.mjs          the DevTools protocol client
```

## License

[MIT](LICENSE).
