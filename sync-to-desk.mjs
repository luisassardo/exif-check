#!/usr/bin/env node
// sync-to-desk.mjs · give this tool's engine to everyone who runs it, without
// forking it.
//
//   node sync-to-desk.mjs           copy engine + vendored reader to every consumer
//   node sync-to-desk.mjs --check   exit 1 if any consumer's copy has drifted
//
// The tool owns the logic. Consumers hold a GENERATED copy they never hand-edit,
// exactly like a design-system consumer (STD-010.2, STD-002.1 category 3). Same
// pattern as 00-core/brand/sync-design.mjs.
//
// Two consumers today:
//   the J-LAB desk   renders the engine as a native screen (STD-024)
//   verify-desk      builds on it instead of reimplementing metadata parsing
//
// The file keeps the name sync-to-desk.mjs even though it now feeds a sibling
// tool as well: check-rules.sh check 5 finds these by exact filename, and being
// discovered by that gate is the point.
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const FILES = ['exif-core.js', 'exif-reader.js'];

// `create: true` means we may make the directory (the desk's vendor dir is ours).
// `create: false` means sync only if the consumer already exists, so this script
// never conjures a tool folder.
const CONSUMERS = [
  {
    path: join(ROOT, '01-web', 'j-lab-site', 'static', 'js', 'vendor'),
    lock: 'exif-check.tool-lock',
    create: true
  },
  {
    path: join(ROOT, '03-j-lab', 'verify-desk'),
    lock: '.engine-lock',
    create: false
  }
];

const check = process.argv.includes('--check');
const hash = (p) => createHash('sha256').update(readFileSync(p)).digest('hex').slice(0, 16);

for (const f of FILES) {
  if (!existsSync(join(HERE, f))) { console.error(`  missing source: ${f}`); process.exit(2); }
}

let drift = 0, copied = 0, synced = 0;

for (const c of CONSUMERS) {
  const label = relative(ROOT, c.path);
  const parentExists = existsSync(dirname(c.path));
  const selfExists = existsSync(c.path);

  if (c.create ? !parentExists : !selfExists) {
    console.log(`  skip   ${label} is not present here`);
    continue;
  }
  if (!check && c.create) mkdirSync(c.path, { recursive: true });

  const lock = { synced_at: null, source: '02-c-lab/exif-check', files: {} };
  synced++;

  for (const f of FILES) {
    const src = join(HERE, f);
    const dst = join(c.path, f);
    const want = hash(src);
    const have = existsSync(dst) ? hash(dst) : 'absent';
    lock.files[f] = want;
    if (want === have) continue;
    if (check) { console.log(`  DRIFT  ${label}/${f}  tool=${want} consumer=${have}`); drift++; }
    else { copyFileSync(src, dst); console.log(`  sync   ${label}/${f}`); copied++; }
  }

  if (!check) {
    lock.synced_at = new Date().toISOString().slice(0, 10);
    writeFileSync(join(c.path, c.lock), JSON.stringify(lock, null, 2) + '\n');
  }
}

if (check) {
  if (drift) {
    console.error(`FAILED: ${drift} file(s) differ. Run: node sync-to-desk.mjs`);
    process.exit(1);
  }
  console.log(`OK: ${synced} consumer(s) run the same engine (${FILES.length} files)`);
} else {
  console.log(copied ? `Done. ${copied} file(s) synced to ${synced} consumer(s).` : 'Already in sync.');
}
