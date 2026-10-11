/**
 * Builds the page into build/: index.html, app.js (the TypeScript of src/app with the package `ua-cryptography`, its
 * WebAssembly and the bundled certificates inlined), styles.css and icon.svg. Plain static files: they open from disk
 * (a file:// URL) and are published as they are on GitHub Pages.
 *
 * The page fetches nothing at runtime: the Content-Security-Policy has connect-src 'none', and the build refuses any
 * other value and any reference to another origin.
 *
 * The version is package.json's and nowhere else; a build of anything but the commit tagged v<version> shows the commit
 * too (0.1.0+1a2b3c4).
 */
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const at = (...parts) => join(root, ...parts);
const watch = process.argv.includes('--watch');
const out = at('build');

async function readRelease() {
  const { version } = JSON.parse(await readFile(at('package.json'), 'utf8'));
  const git = (...args) => {
    try {
      return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return '';
    }
  };
  const tagged = process.env.RELEASE_TAG === `v${version}` || git('tag', '--points-at', 'HEAD').split('\n').includes(`v${version}`);
  const commit = tagged ? '' : git('rev-parse', '--short', 'HEAD');
  return commit ? `${version}+${commit}` : version;
}

/**
 * `import { ROOTS, INTERMEDIATES } from 'bundled-certificates'`: every file of assets/certificates/roots and
 * …/intermediates as { name, base64 } — DER, PEM or a .p7b bundle, handed to the package as they are.
 */
const bundledCertificates = {
  name: 'bundled-certificates',
  setup(builder) {
    builder.onResolve({ filter: /^bundled-certificates$/ }, () => ({ path: 'bundled-certificates', namespace: 'certificates' }));
    builder.onLoad({ filter: /.*/, namespace: 'certificates' }, async () => {
      const list = async (dir) => {
        const names = (await readdir(at('assets/certificates', dir))).filter((n) => !n.startsWith('.')).sort();
        return Promise.all(names.map(async (name) => ({ name, base64: (await readFile(at('assets/certificates', dir, name))).toString('base64') })));
      };
      const contents = `export const ROOTS = ${JSON.stringify(await list('roots'))};\nexport const INTERMEDIATES = ${JSON.stringify(await list('intermediates'))};\n`;
      return { contents, loader: 'js' };
    });
  },
};

/** A classic script, not a module: Chrome loads no module scripts from file:// URLs. */
async function bundle() {
  const result = await build({
    entryPoints: [at('src/app/main.ts')],
    bundle: true,
    format: 'iife',
    target: ['es2022'],
    platform: 'browser',
    // The package's browser entry (its "default" export condition), not the Node.js one that reads the file system.
    conditions: ['browser', 'default'],
    loader: { '.wasm': 'binary' },
    minify: !watch,
    legalComments: 'none',
    charset: 'utf8',
    write: false,
    plugins: [bundledCertificates],
  });
  const output = result.outputFiles[0];
  if (!output) throw new Error('esbuild returned an empty result');
  return output.text;
}

/** Nothing may be fetched at runtime: no references to other origins, and connect-src 'none'. */
function assertSelfContained(html, css) {
  const offenders = [
    [/<script[^>]+\ssrc=["'](?!app\.js["'])/i, '<script src> other than app.js'],
    [/<link[^>]+href=["'](?!(?:styles\.css|icon\.svg)["'])/i, '<link href> other than styles.css and icon.svg'],
  ];
  for (const [pattern, name] of offenders) if (pattern.test(html)) throw new Error(`index.html: ${name}`);
  if (/@import|url\(\s*["']?(?!data:)/i.test(css)) throw new Error('styles.css refers to another file');
  const connect = /http-equiv="Content-Security-Policy" content="[^"]*connect-src ([^;"]*)/.exec(html)?.[1]?.trim();
  if (connect !== "'none'") throw new Error(`The Content-Security-Policy must have connect-src 'none', not ${connect}`);
}

async function buildOnce() {
  const label = await readRelease();
  const [template, styles, appJs] = await Promise.all([readFile(at('src/app/template.html'), 'utf8'), readFile(at('src/app/styles.css'), 'utf8'), bundle()]);
  const html = template.replaceAll('__VERSION__', () => label);
  assertSelfContained(html, styles);

  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await Promise.all([
    writeFile(join(out, 'index.html'), html, 'utf8'),
    writeFile(join(out, 'app.js'), appJs, 'utf8'),
    writeFile(join(out, 'styles.css'), styles, 'utf8'),
    copyFile(at('assets/icon.svg'), join(out, 'icon.svg')),
  ]);
  const kb = (n) => (n / 1024).toFixed(0);
  console.log(`build/ ${label} — index.html, app.js ${kb(Buffer.byteLength(appJs, 'utf8'))} KB, styles.css, icon.svg`);
}

await buildOnce();

if (watch) {
  const { watch: watchDir } = await import('node:fs');
  let pending = null;
  for (const dir of ['src', 'assets']) {
    watchDir(at(dir), { recursive: true }, () => {
      clearTimeout(pending);
      pending = setTimeout(() => buildOnce().catch((error) => console.error(error.message)), 120);
    });
  }
  console.log('watching src/ and assets/ …');
}
