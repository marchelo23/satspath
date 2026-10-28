import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const openapiText = fs.readFileSync(path.join(repoRoot, 'docs/openapi.yaml'), 'utf8');
const apiRefText = fs.readFileSync(path.join(repoRoot, 'docs/API_REFERENCE.md'), 'utf8');
const routerText = fs.readFileSync(path.join(repoRoot, 'crates/satspathd/src/router.rs'), 'utf8');

const PUBLIC_MUTATION_PATHS = new Set([
  '/v1/receive',
  '/v1/dns/resolve',
  '/v1/transparency/verify/inclusion',
  '/v1/transparency/verify/catena',
  '/v1/profile/recover',
  '/v2/resolve',
]);
const PRIVATE_READ_PATHS = new Set(['/v1/invites', '/v1/invites/notifications']);

const REMOVED_LEGACY_DOCS = [
  'docs/SATSPATH_FUNCIONAMIENTO_Y_ROADMAP.md',
  'docs/TECHNICAL_PLAN_MVP.md',
  'docs/TECHNICAL_PLAN_PRODUCTION.md',
  'docs/ark_swap_safety.md',
  'docs/docker_cheatsheet.md',
  'docs/identity_ownership_model.md',
  'docs/mainnet_preview_checklist.md',
  'docs/pear_threat_model.md',
  'docs/protocol_v01_audit.md',
  'docs/release_checklist.md',
  'docs/rfc-0046-s2s-identity.md',
  'docs/routing_model.md',
  'docs/s2s/methods-bolt12.md',
  'docs/satspath_audit_and_todolist.md',
  'docs/satspath_protocol.md',
  'docs/team_workflow.md',
];

test('Silent Payment URI schemas cover receive and amount-bound network variants', () => {
  const schemaBlock = name => openapiText.match(new RegExp(`^    ${name}:\\n([\\s\\S]*?)(?=^    \\w+:|$(?![\\s\\S]))`, 'm'))[1];
  const uriPattern = name => new RegExp(schemaBlock(name).match(/pattern: '([^']+)'/)[1]);
  const receive = uriPattern('SilentPaymentReceivePointer');
  // Shape fixtures only: checksums and curve points are enforced by the runtime.
  for (const [network, address, key] of [
    ['Mainnet', `bc1${'q'.repeat(39)}`, `sp1${'q'.repeat(113)}`],
    ['Testnet', `tb1${'q'.repeat(39)}`, `tsp1${'q'.repeat(113)}`],
    ['Regtest', `bcrt1${'q'.repeat(39)}`, `sprt1${'q'.repeat(113)}`],
  ]) {
    const payable = uriPattern(`${network}SilentPaymentPayableUri`);
    for (const addr of ['', address, address.toUpperCase()]) {
      for (const sp of [key, key.toUpperCase()]) {
        const uri = `bitcoin:${addr}?sp=${sp}`;
        assert.ok(receive.test(uri), uri);
        assert.ok(!payable.test(uri), uri);
        assert.ok(payable.test(`${uri}&amount=0.00021000`), uri);
        assert.ok(!receive.test(`${uri}&lightning=attacker`), uri);
        assert.ok(!payable.test(`${uri}&amount=1e-4`), uri);
        assert.ok(!payable.test(`${uri}&amount=0.00021000&lightning=attacker`), uri);
      }
    }
    const wrongKey = network === 'Mainnet' ? `sprt1${'q'.repeat(113)}` : `sp1${'q'.repeat(113)}`;
    assert.ok(!payable.test(`bitcoin:${address}?sp=${wrongKey}&amount=0.00021000`));
  }
  assert.match(schemaBlock('ReceivePayload'), /SilentPaymentReceivePointer/);
  assert.match(schemaBlock('ReceivePayload'), /PayablePaymentPayload/);
  assert.match(schemaBlock('PayablePaymentPayload'), /PayableOnchainPayload/);
  assert.match(schemaBlock('PayablePaymentPayload'), /ArkPayablePayload/);
  for (const name of ['QuoteOk', 'SendOk', 'PayWalletHandoff']) {
    assert.match(schemaBlock(name), /schemas\/PayablePaymentPayload/, name);
  }
});

test('Ark schemas cover canonical wallet payloads and reachable response rails', () => {
  const schemaBlock = name => openapiText.match(new RegExp(`^    ${name}:\\n([\\s\\S]*?)(?=^    \\w+:|$(?![\\s\\S]))`, 'm'))[1];
  const uriPattern = name => new RegExp(schemaBlock(name).match(/pattern: '([^']+)'/)[1]);
  const receive = uriPattern('ArkReceivePointer');
  const payable = uriPattern('ArkPayablePayload');
  const address = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameetl3ujgrw8089sl27rtp79aqcl0xspkahwnm4teg5lmhe47pxulw9m6rn8';
  assert.ok(receive.test(`bitcoin:?ark=${address}`));
  assert.ok(payable.test(`bitcoin:?ark=${address}&amount=0.00005000`));
  assert.ok(!receive.test(`bitcoin:?ark=${address}&amount=0.00005000`));
  assert.ok(!payable.test(`bitcoin:?ark=${address}&amount=0.00005000&ark=other`));
  assert.match(schemaBlock('QuoteOk'), /schemas\/PayableOnchainMethod/);
  assert.match(schemaBlock('QuoteOk'), /schemas\/ArkMethod/);
  for (const name of ['ReceiveView', 'SendOk']) {
    assert.match(schemaBlock(name), /^\s+- Ark$/m, name);
    assert.match(schemaBlock(name), /^\s+- Onchain$/m, name);
  }
});

/**
 * Parses HTTP operations from `docs/openapi.yaml` along with auth, operationId, and response flags.
 *
 * @param {string} yaml - Raw OpenAPI YAML text.
 * @returns {Array<{path: string, method: string, requiresBearer: boolean, hasOperationId: boolean, hasResponses: boolean}>}
 */
function parseOpenApiOperations(yaml) {
  const lines = yaml.split(/\r?\n/);
  const operations = [];
  let inPaths = false;
  let currentPath = null;
  let currentMethod = null;
  let currentOpLines = [];

  const flushOperation = () => {
    if (currentPath && currentMethod) {
      const block = currentOpLines.join('\n');
      const requiresBearer = /security:\s*\r?\n\s*-\s*bearerAuth:\s*\[\]/.test(block);
      const hasOperationId = /^\s{6}operationId:\s*\S+/m.test(block);
      const hasResponses = /^\s{6}responses:/m.test(block);
      operations.push({
        path: currentPath,
        method: currentMethod.toUpperCase(),
        requiresBearer,
        hasOperationId,
        hasResponses,
      });
    }
    currentMethod = null;
    currentOpLines = [];
  };

  for (const line of lines) {
    if (/^paths:\s*$/.test(line)) {
      inPaths = true;
      continue;
    }
    if (inPaths && /^[a-zA-Z0-9_-]+:\s*$/.test(line)) {
      flushOperation();
      break;
    }
    if (!inPaths) continue;

    const pathMatch = line.match(/^  (\/[^\s:]*):\s*$/);
    if (pathMatch) {
      flushOperation();
      currentPath = pathMatch[1];
      continue;
    }

    const methodMatch = line.match(/^    (get|post|put|delete|head|options|patch):\s*$/);
    if (methodMatch && currentPath) {
      flushOperation();
      currentMethod = methodMatch[1];
      continue;
    }

    if (currentMethod) {
      currentOpLines.push(line);
    }
  }
  flushOperation();
  return operations;
}

test('invite guide requires owner authentication for claims and private lists', () => {
  const guide = fs.readFileSync(path.join(repoRoot, 'docs/invite_flow.md'), 'utf8');
  for (const endpoint of ['POST /v1/claim', 'GET /v1/invites', 'GET /v1/invites/notifications']) {
    const section = guide.split(`- **Endpoint:** \`${endpoint}\``)[1];
    assert.ok(section, endpoint);
    assert.match(section.split('\n')[1], /\*\*Auth:\*\* Bearer token/, endpoint);
  }
  assert.match(guide, /GET \/v1\/claim\?invite_id=<UUID>`\n- \*\*Auth:\*\* None \(Public\)/);
});

/**
 * Extracts endpoint summary rows from `docs/API_REFERENCE.md`.
 *
 * @param {string} markdown - Raw markdown content of `docs/API_REFERENCE.md`.
 * @returns {Array<{method: string, rawPath: string, path: string, requiresBearer: boolean}>}
 */
function parseApiReferenceTable(markdown) {
  const rows = [];
  const regex = /^\|\s*`([A-Z]+)`\s*\|\s*`([^`]+)`\s*\|\s*(Public|Bearer)\s*\|/gm;
  let match;
  while ((match = regex.exec(markdown)) !== null) {
    rows.push({
      method: match[1],
      rawPath: match[2],
      path: match[2].split('?')[0],
      requiresBearer: match[3] === 'Bearer',
    });
  }
  return rows;
}

/**
 * Recursively collects all `.md` files under a directory, excluding `.git`, `node_modules`, and `target`.
 *
 * @param {string} dir - Root directory to traverse.
 * @returns {string[]}
 */
function walkMarkdownFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'target') {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkMarkdownFiles(full));
    } else if (entry.name.endsWith('.md')) {
      results.push(full);
    }
  }
  return results;
}

/**
 * Recursively collects all `.rs` files under a directory, excluding `.git`, `node_modules`, and `target`.
 *
 * @param {string} dir - Root directory to traverse.
 * @returns {string[]}
 */
function walkRustFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'target') {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkRustFiles(full));
    } else if (entry.name.endsWith('.rs')) {
      results.push(full);
    }
  }
  return results;
}

/**
 * Scans Rust source files for `#[ignore]` / `#[ignore = "..."]` test attributes and returns
 * a map keyed by `<relative/path.rs> :: <fn_name>` with the associated ignore reason string.
 *
 * @param {string[]} rustFiles - Absolute paths to `.rs` files to inspect.
 * @returns {Map<string, string>}
 */
function collectIgnoredRustTests(rustFiles) {
  const ignored = new Map();
  for (const file of rustFiles) {
    const rel = path.relative(repoRoot, file).replace(/\\/g, '/');
    const content = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(
      content,
      /^\s*\/\/[\/!].*```(?:rust,)?ignore\b/m,
      `Unexpected ignored doctest in ${rel}; inventory it or make it runnable`,
    );
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const attrMatch = lines[i].match(/^\s*#\[ignore(?:\s*=\s*"([^"]*)")?\s*\]/);
      if (!attrMatch) continue;
      const reason = attrMatch[1] ?? '';
      let fnName = null;
      for (let j = i + 1; j < Math.min(i + 15, lines.length); j += 1) {
        const fnMatch = lines[j].match(/^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(/);
        if (fnMatch) {
          fnName = fnMatch[1];
          break;
        }
      }
      assert.ok(fnName, `Expected test fn following #[ignore] at ${rel}:${i + 1}`);
      ignored.set(`${rel} :: ${fnName}`, reason);
    }
  }
  return ignored;
}

/**
 * Parses the `satspath/` ASCII directory tree block in `docs/architecture.md` into repo-relative paths.
 *
 * @param {string} architectureMarkdown - Raw markdown content of `docs/architecture.md`.
 * @returns {string[]}
 */
function parseArchitectureTreePaths(architectureMarkdown) {
  const blockMatch = architectureMarkdown.match(/```text\r?\nsatspath\/\r?\n([\s\S]*?)```/);
  assert.ok(blockMatch, 'Expected satspath/ workspace tree block in docs/architecture.md');
  const stack = [];
  const paths = [];
  for (const line of blockMatch[1].split(/\r?\n/)) {
    const entryMatch = line.match(/^((?:│   |    )*)(?:├── |└── )([^\s#]+)/);
    if (!entryMatch) continue;
    const depth = entryMatch[1].length / 4;
    const segment = entryMatch[2].replace(/\/$/, '');
    stack.length = depth;
    stack[depth] = segment;
    paths.push(stack.join('/'));
  }
  return paths;
}

test('OpenAPI 3.0.3 operations have operationId, responses, and match router auth rules', () => {
  const operations = parseOpenApiOperations(openapiText);
  assert.equal(operations.length, 56, 'Expected all 56 HTTP operations in docs/openapi.yaml');

  for (const op of operations) {
    assert.ok(op.hasOperationId, `${op.method} ${op.path} must define an operationId`);
    assert.ok(op.hasResponses, `${op.method} ${op.path} must define responses`);

    const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(op.method);
    const expectedBearer = (isMutation && !PUBLIC_MUTATION_PATHS.has(op.path)) || PRIVATE_READ_PATHS.has(op.path);
    assert.equal(
      op.requiresBearer,
      expectedBearer,
      `Auth mismatch for ${op.method} ${op.path} in docs/openapi.yaml`,
    );
  }
});

test('API_REFERENCE.md endpoint table matches OpenAPI operations and router auth rules', () => {
  const operations = parseOpenApiOperations(openapiText);
  const tableRows = parseApiReferenceTable(apiRefText);
  assert.ok(tableRows.length >= 54, 'Expected endpoint summary table in docs/API_REFERENCE.md');

  const openApiSet = new Set(operations.map(op => `${op.method} ${op.path}`));
  const tableSet = new Set(tableRows.map(row => `${row.method} ${row.path}`));

  assert.deepEqual(
    [...tableSet].sort(),
    [...openApiSet].sort(),
    'API_REFERENCE.md endpoint table and openapi.yaml operations must match',
  );

  for (const row of tableRows) {
    const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(row.method);
    const expectedBearer = (isMutation && !PUBLIC_MUTATION_PATHS.has(row.path)) || PRIVATE_READ_PATHS.has(row.path);
    assert.equal(
      row.requiresBearer,
      expectedBearer,
      `Auth mismatch for ${row.method} ${row.rawPath} in docs/API_REFERENCE.md`,
    );
  }
});

test('satspathd router.rs public mutation allow-list matches documented public mutations', () => {
  for (const pubPath of PUBLIC_MUTATION_PATHS) {
    if (pubPath === '/v2/resolve') {
      assert.match(routerText, /path == "\/v2\/resolve"/);
    } else {
      assert.ok(
        routerText.includes(`path == "${pubPath}"`),
        `Expected router.rs public mutation allow-list to contain ${pubPath}`,
      );
    }
  }
});

test('every local $ref in docs/openapi.yaml resolves to a defined component', () => {
  const refs = [...openapiText.matchAll(/\$ref:\s*['"]?#\/components\/(schemas|parameters|headers|securitySchemes|responses)\/([A-Za-z0-9_]+)['"]?/g)];
  assert.ok(refs.length > 0, 'Expected component $refs in docs/openapi.yaml');

  for (const [, section, name] of refs) {
    const definitionRegex = new RegExp(`^  ${section}:[\\s\\S]*?^    ${name}:\\s*$`, 'm');
    assert.match(
      openapiText,
      definitionRegex,
      `Missing #/components/${section}/${name} in docs/openapi.yaml`,
    );
  }
});

test('obsolete docs are removed and all markdown relative links resolve', () => {
  for (const rel of REMOVED_LEGACY_DOCS) {
    assert.equal(
      fs.existsSync(path.join(repoRoot, rel)),
      false,
      `Obsolete doc ${rel} should remain removed`,
    );
  }

  const mdFiles = [
    path.join(repoRoot, 'README.md'),
    path.join(repoRoot, 'ROADMAP.md'),
    path.join(repoRoot, 'walktrough.md'),
    path.join(repoRoot, 'security_tests.md'),
    path.join(repoRoot, 'sdk/satspath-p2p/README.md'),
    path.join(repoRoot, 'crates/satspath-conformance/README.md'),
    ...walkMarkdownFiles(path.join(repoRoot, 'deploy')),
    ...walkMarkdownFiles(path.join(repoRoot, 'examples')),
    ...walkMarkdownFiles(path.join(repoRoot, 'docs')),
  ];

  for (const file of mdFiles) {
    const content = fs.readFileSync(file, 'utf8').replace(/```[\s\S]*?```/g, '');
    const linkRegex = /\[[^\]]+\]\(([^)#\s]+)(?:#[^)]*)?\)/g;
    let match;
    while ((match = linkRegex.exec(content)) !== null) {
      const target = match[1];
      if (/^(https?:|mailto:|bitcoin:|lightning:|ark:|file:)/.test(target)) continue;
      const resolved = path.resolve(path.dirname(file), target);
      assert.ok(
        fs.existsSync(resolved),
        `Broken markdown link in ${path.relative(repoRoot, file)} -> ${target}`,
      );
    }
  }
});

test('README workspace table matches actual Cargo workspace members', () => {
  const manifest = fs.readFileSync(path.join(repoRoot, 'Cargo.toml'), 'utf8');
  const readme = fs.readFileSync(path.join(repoRoot, 'README.md'), 'utf8');
  const membersBlock = manifest.match(/members\s*=\s*\[([\s\S]*?)\]/);
  assert.ok(membersBlock, 'Expected a workspace member list');
  const members = [...membersBlock[1].matchAll(/"(crates\/[^"\s]+)"/g)].map(match => match[1]);
  const documented = [...readme.matchAll(/^\| \*\*`(crates\/[^`]+)`\*\* \|/gm)].map(match => match[1]);
  assert.deepEqual(documented.sort(), members.sort(), 'Update workspace docs when adding/removing crates');
  assert.ok(fs.existsSync(path.join(repoRoot, 'crates/satspath-witness/src/bin/satspath-gossip.rs')));
});

test('CLI setup examples configure the state variable read by the native implementation', () => {
  const source = fs.readFileSync(path.join(repoRoot, 'crates/satspath-core/src/lib.rs'), 'utf8');
  const stateFunction = source.match(/pub fn default_data_dir\(\)[\s\S]*?\n\}/);
  assert.ok(stateFunction, 'Expected native CLI directory selection');
  const variable = stateFunction[0].match(/std::env::var\("([^"]+)"\)/)?.[1];
  assert.ok(variable, 'Expected an environment override in default_data_dir');
  for (const file of ['README.md', 'examples/demo_flow.md']) {
    const text = fs.readFileSync(path.join(repoRoot, file), 'utf8');
    assert.ok(text.includes(`export ${variable}=`), `${file} must use the real CLI state override`);
    assert.doesNotMatch(text, /export SATSPATH_DATA_DIR=/);
  }
});

test('docs/README.md publishes 4-surface x 5-stage lifecycle capability matrix and reconciles #196', () => {
  const docsIndex = fs.readFileSync(path.join(repoRoot, 'docs/README.md'), 'utf8');
  const lifecycleSection = docsIndex.match(
    /^## Lifecycle capability matrix by interface\r?\n([\s\S]*?)(?=^## )/m,
  );
  assert.ok(lifecycleSection, 'Expected ## Lifecycle capability matrix by interface in docs/README.md');
  assert.match(
    lifecycleSection[1],
    /^\|\s*Surface\s*\|\s*Discovery\s*\|\s*Amountless receive\s*\|\s*Payable quotes\s*\|\s*Approval\s*\|\s*External execution\s*\|$/m,
    'Lifecycle capability matrix must distinguish Discovery, Amountless receive, Payable quotes, Approval, and External execution',
  );

  for (const surface of [
    '**CLI** (`satspath-cli`)',
    '**Daemon HTTP** (`satspathd`)',
    '**Browser WASM** (`satspath-wasm`)',
    '**Dashboard UI** (`satspathd/src/index.html`)',
  ]) {
    const row = lifecycleSection[1]
      .split(/\r?\n/)
      .find(line => line.startsWith(`| ${surface} |`));
    assert.ok(row, `Expected lifecycle matrix row for ${surface}`);
    const cells = row
      .split('|')
      .slice(1, -1)
      .map(cell => cell.trim());
    assert.equal(cells.length, 6, `Expected 6 columns for ${surface}`);
    for (const cell of cells) {
      assert.ok(cell.length > 0, `Empty capability cell in row ${surface}`);
    }
  }

  const reconciledSection = docsIndex.match(
    /^## Reconciled implementation issues\r?\n([\s\S]*?)(?=^## )/m,
  );
  assert.ok(reconciledSection, 'Expected ## Reconciled implementation issues in docs/README.md');
  assert.match(reconciledSection[1], /https:\/\/github\.com\/satspath\/satspath\/issues\/196/);
  assert.match(reconciledSection[1], /docs\/integrations\/README\.md/);
  assert.match(reconciledSection[1], /satspath-conformance wallet --adapter/);
});

test('docs/README.md ignored-test inventory matches workspace #[ignore] tests 1-to-1 and CI regtest jobs', () => {
  const rustFiles = [
    ...walkRustFiles(path.join(repoRoot, 'crates')),
    ...walkRustFiles(path.join(repoRoot, 'fuzz')),
  ];
  const actualIgnored = collectIgnoredRustTests(rustFiles);
  assert.ok(actualIgnored.size > 0, 'Expected workspace #[ignore] tests to inventory');

  const docsIndex = fs.readFileSync(path.join(repoRoot, 'docs/README.md'), 'utf8');
  const inventorySection = docsIndex.match(/^## Ignored-test inventory\r?\n([\s\S]*?)(?=^## )/m);
  assert.ok(inventorySection, 'Expected ## Ignored-test inventory in docs/README.md');

  const documentedIgnored = new Map();
  const activeCiRegtestEntries = [];
  const rowRegex = /^\|\s*`([^`]+\s::\s[A-Za-z0-9_]+)`\s*\|\s*`([^`]*)`\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*\*\*([^*]+)\*\*\s*\|$/gm;
  let match;
  while ((match = rowRegex.exec(inventorySection[1])) !== null) {
    const [, testKey, reason, covered, command, classification] = match;
    assert.ok(!documentedIgnored.has(testKey), `Duplicate ignored-test entry: ${testKey}`);
    assert.ok(covered.trim().length > 0, `Missing covered capability for ${testKey}`);
    assert.ok(command.trim().length > 0, `Missing command/CI job for ${testKey}`);
    documentedIgnored.set(testKey, reason);
    if (classification.trim() === 'Active CI regtest coverage') {
      activeCiRegtestEntries.push(testKey);
    }
  }

  assert.deepEqual(
    [...documentedIgnored.keys()].sort(),
    [...actualIgnored.keys()].sort(),
    'docs/README.md ignored-test inventory must match actual #[ignore] tests 1-to-1',
  );
  for (const [key, actualReason] of actualIgnored.entries()) {
    assert.equal(
      documentedIgnored.get(key),
      actualReason,
      `Ignore reason mismatch in docs/README.md for ${key}`,
    );
  }

  const ciWorkflows = [
    fs.readFileSync(path.join(repoRoot, '.github/workflows/ci.yml'), 'utf8'),
    fs.readFileSync(path.join(repoRoot, '.github/workflows/daemon-e2e.yml'), 'utf8'),
  ].join('\n');
  assert.equal(activeCiRegtestEntries.length, 4, 'Expected 4 active CI regtest ignored tests');
  for (const testKey of activeCiRegtestEntries) {
    const [relFile, fnName] = testKey.split(' :: ');
    const testTarget = path.basename(relFile, '.rs');
    const runsWholeTargetIgnored = new RegExp(`--test\\s+${testTarget}\\b[^\\n]*--ignored`).test(ciWorkflows);
    const runsNamedFnIgnored = new RegExp(`--ignored\\s+${fnName}\\b`).test(ciWorkflows);
    assert.ok(
      runsWholeTargetIgnored || runsNamedFnIgnored,
      `Active CI regtest test ${testKey} must be invoked with --ignored in GitHub workflows`,
    );
  }
});

test('architecture workspace tree paths exist on disk and P2P CLI import example matches clap syntax', () => {
  const architecture = fs.readFileSync(path.join(repoRoot, 'docs/architecture.md'), 'utf8');
  const treePaths = parseArchitectureTreePaths(architecture);
  assert.ok(treePaths.length >= 15, 'Expected crate and workspace entries in docs/architecture.md tree');
  for (const relPath of treePaths) {
    assert.ok(
      fs.existsSync(path.join(repoRoot, relPath)),
      `Nonexistent workspace path in docs/architecture.md: ${relPath}`,
    );
  }

  const cliMain = fs.readFileSync(path.join(repoRoot, 'crates/satspath-cli/src/main.rs'), 'utf8');
  assert.match(cliMain, /Import\s*\{\s*(?:\/\/\/[^\n]*\r?\n\s*)?file:\s*Option<String>,/);
  const p2pReadme = fs.readFileSync(path.join(repoRoot, 'sdk/satspath-p2p/README.md'), 'utf8');
  assert.match(p2pReadme, /^satspath import received-profile\.json$/m);
  assert.doesNotMatch(p2pReadme, /satspath import --file\b/);
});
