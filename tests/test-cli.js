/**
 * AegisMCP - CLI Automation Integration Test Suite
 * Tests command-line interface execution, flags, exit codes, and output formats.
 */

'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFile, spawn } = require('node:child_process');

const CLI_PATH = path.resolve(__dirname, '../bin/aegis-mcp.js');

function runCli(args, options = {}) {
  return new Promise((resolve) => {
    execFile('node', [CLI_PATH, ...args], {
      timeout: options.timeout || 10000,
      env: { ...process.env, ...options.env },
      cwd: options.cwd || process.cwd()
    }, (error, stdout, stderr) => {
      resolve({
        code: error ? (error.code ?? (error.killed ? 143 : 1)) : 0,
        stdout: stdout || '',
        stderr: stderr || '',
        error
      });
    });
  });
}

async function runCliTests() {
  console.log('🧪 Testing CLI Automation & Command-Line Interface...');

  // 1. Help flag (--help, -h)
  {
    const res1 = await runCli(['--help']);
    assert.strictEqual(res1.code, 0, '--help must exit with 0');
    assert(res1.stdout.includes('AegisMCP - Zero-Trust Security Firewall'), 'Must include title in help output');
    assert(res1.stdout.includes('--serve'), 'Must document --serve');
    assert(res1.stdout.includes('--proxy'), 'Must document --proxy');
    assert(res1.stdout.includes('--pipeline'), 'Must document --pipeline');
    assert(res1.stdout.includes('--supervise'), 'Must document --supervise');

    const res2 = await runCli(['-h']);
    assert.strictEqual(res2.code, 0, '-h must exit with 0');
    assert(res2.stdout.includes('USAGE:'), 'Must include usage in short help');
    console.log('    ✔ --help and -h flags display manual and exit 0 PASSED');
  }

  // 2. Client configuration generation (--generate-config)
  {
    const clients = ['claude', 'cursor', 'zed', 'windsurf', 'all'];
    for (const client of clients) {
      const res = await runCli(['--generate-config', client]);
      assert.strictEqual(res.code, 0, `--generate-config ${client} must exit with 0`);
      assert(res.stdout.includes('AegisMCP Client Configuration for'), `Must confirm config generation for ${client}`);
      assert(res.stdout.includes('aegis-') || res.stdout.includes('mcpServers') || res.stdout.includes('context_servers'), 'Must output JSON config snippet');
    }
    console.log('    ✔ --generate-config (claude, cursor, zed, windsurf, all) PASSED');
  }

  // 3. Dynamic Rule Synthesizer (--synthesize)
  {
    const res = await runCli(['--synthesize', 'read_file']);
    assert.strictEqual(res.code, 0, '--synthesize read_file must exit with 0');
    assert(res.stdout.includes('Synthesizing Zero-Trust Security Rules'), 'Must initiate synthesis');
    assert(res.stdout.includes('SYN-'), 'Must output synthesized rule ID');
    assert(res.stdout.includes('Synthesized 2 custom security defense rules'), 'Must show synthesized rule count');
    console.log('    ✔ --synthesize <tool> auto-generates security rules PASSED');
  }

  // 4. Automated Exploit Test (--exploit-test)
  {
    const res = await runCli(['--exploit-test', 'read_file']);
    assert.strictEqual(res.code, 0, '--exploit-test must exit with 0');
    assert(res.stdout.includes('Automated Adversarial Exploit Audit'), 'Must run exploit audit');
    assert(res.stdout.includes('EXPLOIT IMMUNITY SCORECARD: [Grade: A+]'), 'Must show scorecard');
    assert(res.stdout.includes('Total Weaponized Exploits: 19'), 'Must count 19 exploits');
    assert(res.stdout.includes('Vulnerable / Unmitigated:  0'), 'Must report 0 unmitigated');
    console.log('    ✔ --exploit-test <tool> runs adversarial audit and auto-remediation PASSED');
  }

  // 5. Automated Protocol Fuzzer (--fuzz)
  {
    const res = await runCli(['--fuzz', '--tool', 'read_file']);
    assert.strictEqual(res.code, 0, '--fuzz must exit with 0');
    assert(res.stdout.includes('Aegis Protocol Fuzzer'), 'Must run fuzzer');
    assert(res.stdout.includes('Overall Grade:') && res.stdout.includes('100%'), 'Must report 100% resilience');
    assert(res.stdout.includes('Total Adversarial Vectors:'), 'Must report adversarial vectors');
    console.log('    ✔ --fuzz executes automated schema fuzzing PASSED');
  }

  // 6. Cryptographic Ledger Verification (--verify-ledger)
  {
    const res = await runCli(['--verify-ledger']);
    assert.strictEqual(res.code, 0, '--verify-ledger must exit with 0');
    assert(res.stdout.includes('cryptographic ledger integrity check'), 'Must run ledger verification');
    assert(res.stdout.includes('Ledger verified intact'), 'Must confirm cryptographic integrity');
    console.log('    ✔ --verify-ledger validates cryptographic Merkle hash chain PASSED');
  }

  // 7. Time-Travel Forensics & Tamper Localization (--forensics)
  {
    const res = await runCli(['--forensics']);
    assert.strictEqual(res.code, 0, '--forensics must exit with 0');
    assert(res.stdout.includes('Aegis Deep Cryptographic Ledger Forensics'), 'Must run forensics');
    assert(res.stdout.includes('Adversary Tamper Simulation'), 'Must simulate tamper');
    assert(res.stdout.includes('Tampered Block Index: #1'), 'Must localize tampered block');
    assert(res.stdout.includes('CHAIN RESTORED INTACT'), 'Must confirm chain restoration');
    console.log('    ✔ --forensics localizes tampering and executes 1-click self-healing PASSED');
  }

  // 8. DAG Pipeline Execution (--pipeline <file>)
  {
    // 8.1 Missing pipeline file argument
    const resMissing = await runCli(['--pipeline']);
    assert.strictEqual(resMissing.code, 1, '--pipeline without argument must exit 1');
    assert(resMissing.stderr.includes('--pipeline requires a path'), 'Must report error for missing file argument');

    // 8.2 Non-existent pipeline file
    const resNotFound = await runCli(['--pipeline', '/tmp/nonexistent-pipeline-123456.json']);
    assert.strictEqual(resNotFound.code, 1, '--pipeline with nonexistent file must exit 1');
    assert(resNotFound.stderr.includes('Pipeline execution failed'), 'Must report failure on missing file');

    // 8.3 Invalid JSON pipeline file
    const tmpDir = os.tmpdir();
    const badJsonPath = path.join(tmpDir, `bad-pipeline-${Date.now()}.json`);
    fs.writeFileSync(badJsonPath, '{ invalid json');
    const resBadJson = await runCli(['--pipeline', badJsonPath]);
    fs.unlinkSync(badJsonPath);
    assert.strictEqual(resBadJson.code, 1, '--pipeline with bad JSON must exit 1');
    assert(resBadJson.stderr.includes('Pipeline execution failed'), 'Must report parse error');

    // 8.4 Valid DAG Pipeline with concurrent tiers
    const validPipeline = {
      id: 'cli-test-pipeline',
      name: 'CLI Multi-Tier Automated Pipeline',
      nodes: [
        {
          id: 'step_write_token',
          server: 'virtual_crypto',
          tool: 'generate_token',
          params: { bytes: 16, format: 'hex' }
        },
        {
          id: 'step_store_token',
          server: 'virtual_memory',
          tool: 'set_key',
          params: {
            key: 'auth_token',
            value: '{{nodes.step_write_token.token}}',
            tags: ['auth', 'session']
          }
        },
        {
          id: 'step_read_back',
          server: 'virtual_memory',
          tool: 'get_key',
          params: {
            key: 'auth_token',
            tokenRef: '{{nodes.step_store_token.key}}'
          }
        }
      ]
    };
    const validJsonPath = path.join(tmpDir, `valid-pipeline-${Date.now()}.json`);
    fs.writeFileSync(validJsonPath, JSON.stringify(validPipeline, null, 2));

    const resValid = await runCli(['--pipeline', validJsonPath]);
    fs.unlinkSync(validJsonPath);

    assert.strictEqual(resValid.code, 0, '--pipeline valid file must exit 0');
    assert(resValid.stdout.includes('Executing DAG Pipeline'), 'Must log pipeline execution');
    assert(resValid.stdout.includes('Topological Partitioning:'), 'Must show topological partitioning');
    assert(resValid.stdout.includes('COMPLETED in'), 'Must confirm completion');
    assert(resValid.stdout.includes('Steps Executed: 3'), 'Must report 3 executed steps');
    assert(resValid.stdout.includes('Tiers Executed: 3'), 'Must report 3 tiers');
    console.log('    ✔ --pipeline <file> executes multi-tier DAG workflows and outputs stats PASSED');
  }

  // 9. External Server Proxy Argument Guard (--proxy)
  {
    const resNoProxyCmd = await runCli(['--proxy']);
    assert.strictEqual(resNoProxyCmd.code, 1, '--proxy without argument must exit 1');
    assert(resNoProxyCmd.stderr.includes('--proxy requires an upstream command'), 'Must report missing upstream command');
    console.log('    ✔ --proxy input guard detects missing command PASSED');
  }

  console.log('✅ CLI Automation: All 9 test groups passed!\n');
}

module.exports = { runCliTests };

if (require.main === module) {
  runCliTests().catch(err => {
    console.error('❌ CLI Tests Failed:', err);
    process.exit(1);
  });
}
