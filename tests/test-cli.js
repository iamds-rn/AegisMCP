/**
 * AegisMCP - CLI Automation Integration Test Suite
 * Comprehensive automated verification of command-line interface execution:
 * 1. Informational Flags & Versioning (Exit Code 0)
 * 2. Error Handling & Invalid Invocations (Exit Code 1)
 * 3. Positional vs Flag Command Equivalence
 * 4. Stdio Subprocess Lifecycle & JSON-RPC Ping Probe
 * 5. HTTP Gateway Serve Lifecycle & Health Endpoint
 */

'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const { execFile, spawn } = require('node:child_process');
const pkg = require('../package.json');

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

function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}

async function runCliTests() {
  console.log('🧪 Testing CLI Automation & Command-Line Interface...');

  // =========================================================================
  // Section 1: Informational Flags & Versioning (Exit Code 0)
  // =========================================================================
  {
    // 1.1 --help
    const resHelp = await runCli(['--help']);
    assert.strictEqual(resHelp.code, 0, '--help must exit with code 0');
    assert(resHelp.stdout.includes('AegisMCP - Zero-Trust Security Firewall'), 'Must include title in help output');
    assert(resHelp.stdout.includes('--serve'), 'Must document --serve');
    assert(resHelp.stdout.includes('--proxy'), 'Must document --proxy');
    assert(resHelp.stdout.includes('--pipeline'), 'Must document --pipeline');
    assert(resHelp.stdout.includes('--supervise'), 'Must document --supervise');

    // 1.2 -h
    const resShortHelp = await runCli(['-h']);
    assert.strictEqual(resShortHelp.code, 0, '-h must exit with code 0');
    assert(resShortHelp.stdout.includes('USAGE:'), 'Must include usage in short help');

    // 1.3 Empty arguments (defaults to help manual with exit 0)
    const resEmpty = await runCli([]);
    assert.strictEqual(resEmpty.code, 0, 'Empty args must exit with code 0');
    assert(resEmpty.stdout.includes('USAGE:'), 'Empty args must display help');

    // 1.4 Positional help
    const resPosHelp = await runCli(['help']);
    assert.strictEqual(resPosHelp.code, 0, 'Positional help must exit with code 0');
    assert(resPosHelp.stdout.includes('USAGE:'), 'Positional help must display help');

    // 1.5 --version
    const resVer = await runCli(['--version']);
    assert.strictEqual(resVer.code, 0, '--version must exit with code 0');
    assert.strictEqual(resVer.stdout.trim(), `v${pkg.version}`, `--version must output v${pkg.version}`);

    // 1.6 -v
    const resShortVer = await runCli(['-v']);
    assert.strictEqual(resShortVer.code, 0, '-v must exit with code 0');
    assert.strictEqual(resShortVer.stdout.trim(), `v${pkg.version}`, `-v must output v${pkg.version}`);

    // 1.7 Positional version
    const resPosVer = await runCli(['version']);
    assert.strictEqual(resPosVer.code, 0, 'Positional version must exit with code 0');
    assert.strictEqual(resPosVer.stdout.trim(), `v${pkg.version}`);

    console.log('    ✔ Section 1: Help and version flags display correctly and exit 0 PASSED');
  }

  // =========================================================================
  // Section 2: Error Handling & Invalid Invocations (Exit Code 1)
  // =========================================================================
  {
    // 2.1 Unknown positional command
    const resUnknownCmd = await runCli(['nonexistent-subcommand-xyz']);
    assert.strictEqual(resUnknownCmd.code, 1, 'Unknown command must exit with code 1');
    assert(resUnknownCmd.stderr.includes('Unknown command'), 'Must report unknown command on stderr');

    // 2.2 Unknown option flag
    const resUnknownFlag = await runCli(['--nonexistent-flag-xyz']);
    assert.strictEqual(resUnknownFlag.code, 1, 'Unknown flag must exit with code 1');
    assert(resUnknownFlag.stderr.includes('Unrecognized flag'), 'Must report unrecognized flag on stderr');

    // 2.3 Dangling --mode option
    const resDanglingMode = await runCli(['--mode']);
    assert.strictEqual(resDanglingMode.code, 1, 'Dangling --mode must exit with code 1');
    assert(resDanglingMode.stderr.includes('--mode requires a value'), 'Must report missing --mode value');

    // 2.4 Invalid --mode value
    const resInvalidMode = await runCli(['--mode', 'INVALID_MODE']);
    assert.strictEqual(resInvalidMode.code, 1, 'Invalid --mode must exit with code 1');
    assert(resInvalidMode.stderr.includes('Invalid --mode'), 'Must report invalid --mode value');

    // 2.5 Dangling --port option
    const resDanglingPort = await runCli(['--port']);
    assert.strictEqual(resDanglingPort.code, 1, 'Dangling --port must exit with code 1');
    assert(resDanglingPort.stderr.includes('--port requires a valid port number'), 'Must report missing port value');

    // 2.6 Non-numeric --port option
    const resAlphaPort = await runCli(['--port', 'not-a-port']);
    assert.strictEqual(resAlphaPort.code, 1, 'Non-numeric --port must exit with code 1');
    assert(resAlphaPort.stderr.includes('--port requires a valid port number'), 'Must report invalid port value');

    // 2.7 Out of range --port
    const resOutOfRangePort = await runCli(['--port', '99999']);
    assert.strictEqual(resOutOfRangePort.code, 1, 'Out-of-range --port must exit with code 1');
    assert(resOutOfRangePort.stderr.includes('--port requires a valid port number'), 'Must report out-of-range port');

    // 2.8 Missing argument for --proxy
    const resNoProxy = await runCli(['--proxy']);
    assert.strictEqual(resNoProxy.code, 1, '--proxy without upstream command must exit with code 1');
    assert(resNoProxy.stderr.includes('--proxy requires an upstream command'), 'Must report missing upstream command');

    // 2.9 Missing argument for --pipeline
    const resNoPipeline = await runCli(['--pipeline']);
    assert.strictEqual(resNoPipeline.code, 1, '--pipeline without path must exit with code 1');
    assert(resNoPipeline.stderr.includes('--pipeline requires a path'), 'Must report missing pipeline path');

    // 2.10 Nonexistent file for --pipeline
    const resNonexistentPipe = await runCli(['--pipeline', '/tmp/nonexistent-pipeline-9999.json']);
    assert.strictEqual(resNonexistentPipe.code, 1, '--pipeline with nonexistent file must exit with code 1');
    assert(resNonexistentPipe.stderr.includes('Pipeline execution failed'), 'Must report pipeline file not found');

    // 2.11 Corrupted JSON for --pipeline
    const tmpDir = os.tmpdir();
    const badJsonFile = path.join(tmpDir, `bad-pipe-${Date.now()}.json`);
    fs.writeFileSync(badJsonFile, '{ invalid: json syntax');
    const resBadPipe = await runCli(['--pipeline', badJsonFile]);
    try { fs.unlinkSync(badJsonFile); } catch {}
    assert.strictEqual(resBadPipe.code, 1, '--pipeline with malformed JSON must exit with code 1');
    assert(resBadPipe.stderr.includes('Pipeline execution failed'), 'Must report JSON parse failure');

    // 2.12 Invalid client for config command
    const resInvalidClient = await runCli(['config', 'unknown_editor_client']);
    assert.strictEqual(resInvalidClient.code, 1, 'config with unknown client must exit with code 1');
    assert(resInvalidClient.stderr.includes('Error generating config'), 'Must report unsupported client');

    console.log('    ✔ Section 2: Invalid commands, flags, and missing arguments exit 1 PASSED');
  }

  // =========================================================================
  // Section 3: Positional vs Flag Command Equivalence
  // =========================================================================
  {
    // 3.1 config claude vs --config claude vs --generate-config claude
    const resPosConfig = await runCli(['config', 'claude']);
    assert.strictEqual(resPosConfig.code, 0, 'config claude must exit with code 0');
    assert(resPosConfig.stdout.includes('Claude Desktop') && resPosConfig.stdout.includes('mcpServers'));

    const resFlagConfig1 = await runCli(['--config', 'claude']);
    assert.strictEqual(resFlagConfig1.code, 0, '--config claude must exit with code 0');
    assert(resFlagConfig1.stdout.includes('Claude Desktop') && resFlagConfig1.stdout.includes('mcpServers'));

    const resFlagConfig2 = await runCli(['--generate-config', 'claude']);
    assert.strictEqual(resFlagConfig2.code, 0, '--generate-config claude must exit with code 0');
    assert(resFlagConfig2.stdout.includes('Claude Desktop') && resFlagConfig2.stdout.includes('mcpServers'));

    // Verify all editors work positionally: cursor, zed, windsurf, all
    for (const c of ['cursor', 'zed', 'windsurf', 'all']) {
      const resC = await runCli(['config', c]);
      assert.strictEqual(resC.code, 0, `config ${c} must exit with code 0`);
      assert(resC.stdout.includes('AegisMCP Client Configuration for'));
    }

    // 3.2 verify vs --verify vs --verify-ledger
    const resPosVerify = await runCli(['verify']);
    assert.strictEqual(resPosPosVerifySafe(resPosVerify), true, 'verify must succeed');
    assert(resPosVerify.stdout.includes('Ledger verified intact'));

    const resFlagVerify = await runCli(['--verify']);
    assert.strictEqual(resFlagVerify.code, 0, '--verify must succeed');
    assert(resFlagVerify.stdout.includes('Ledger verified intact'));

    const resFlagVerifyLedger = await runCli(['--verify-ledger']);
    assert.strictEqual(resFlagVerifyLedger.code, 0, '--verify-ledger must succeed');
    assert(resFlagVerifyLedger.stdout.includes('Ledger verified intact'));

    // 3.3 forensics vs --forensics
    const resPosForensics = await runCli(['forensics']);
    assert.strictEqual(resPosForensics.code, 0, 'forensics must exit with code 0');
    assert(resPosForensics.stdout.includes('CHAIN RESTORED INTACT'));

    const resFlagForensics = await runCli(['--forensics']);
    assert.strictEqual(resFlagForensics.code, 0, '--forensics must exit with code 0');
    assert(resFlagForensics.stdout.includes('CHAIN RESTORED INTACT'));

    // 3.4 synthesize read_file vs --synthesize read_file
    const resPosSyn = await runCli(['synthesize', 'read_file']);
    assert.strictEqual(resPosSyn.code, 0, 'synthesize read_file must exit with code 0');
    assert(resPosSyn.stdout.includes('SYN-') && resPosSyn.stdout.includes('Synthesized'));

    const resFlagSyn = await runCli(['--synthesize', 'read_file']);
    assert.strictEqual(resFlagSyn.code, 0, '--synthesize read_file must exit with code 0');
    assert(resFlagSyn.stdout.includes('SYN-') && resFlagSyn.stdout.includes('Synthesized'));

    // 3.5 exploit-test read_file vs --exploit-test read_file
    const resPosExp = await runCli(['exploit-test', 'read_file']);
    assert.strictEqual(resPosExp.code, 0, 'exploit-test read_file must exit with code 0');
    assert(resPosExp.stdout.includes('EXPLOIT IMMUNITY SCORECARD'));

    const resFlagExp = await runCli(['--exploit-test', 'read_file']);
    assert.strictEqual(resFlagExp.code, 0, '--exploit-test read_file must exit with code 0');
    assert(resFlagExp.stdout.includes('EXPLOIT IMMUNITY SCORECARD'));

    // 3.6 fuzz --tool read_file vs --fuzz --tool read_file
    const resPosFuzz = await runCli(['fuzz', '--tool', 'read_file']);
    assert.strictEqual(resPosFuzz.code, 0, 'fuzz --tool read_file must exit with code 0');
    assert(resPosFuzz.stdout.includes('Aegis Protocol Fuzzer'));

    const resFlagFuzz = await runCli(['--fuzz', '--tool', 'read_file']);
    assert.strictEqual(resFlagFuzz.code, 0, '--fuzz --tool read_file must exit with code 0');
    assert(resFlagFuzz.stdout.includes('Aegis Protocol Fuzzer'));

    // 3.7 pipeline <file> vs --pipeline <file>
    const tmpDir2 = os.tmpdir();
    const testPipelineFile = path.join(tmpDir2, `pipeline-equiv-${Date.now()}.json`);
    fs.writeFileSync(testPipelineFile, JSON.stringify({
      id: 'pipeline-equivalence-test',
      nodes: [
        { id: 'step_1', server: 'virtual_crypto', tool: 'generate_token', params: { bytes: 8 } }
      ]
    }));

    const resPosPipe = await runCli(['pipeline', testPipelineFile]);
    assert.strictEqual(resPosPipe.code, 0, 'pipeline <file> must exit with code 0');
    assert(resPosPipe.stdout.includes('COMPLETED in'));

    const resFlagPipe = await runCli(['--pipeline', testPipelineFile]);
    assert.strictEqual(resFlagPipe.code, 0, '--pipeline <file> must exit with code 0');
    assert(resFlagPipe.stdout.includes('COMPLETED in'));
    try { fs.unlinkSync(testPipelineFile); } catch {}

    console.log('    ✔ Section 3: Positional subcommands and flag aliases execute equivalently PASSED');
  }

  // =========================================================================
  // Section 4: Stdio Subprocess Lifecycle & Ping Probe
  // =========================================================================
  {
    const stdioChild = spawn('node', [CLI_PATH, 'stdio', '--mode', 'ENFORCE'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let pingReceived = false;
    let stdoutBuffer = '';

    const pingPromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Stdio ping probe response timed out after 5000ms'));
      }, 5000);

      stdioChild.stdout.on('data', (chunk) => {
        stdoutBuffer += chunk.toString();
        const lines = stdoutBuffer.split('\n');
        stdoutBuffer = lines.pop(); // keep partial

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            const parsed = JSON.parse(trimmed);
            if (parsed.id === 8888 && parsed.result !== undefined) {
              pingReceived = true;
              clearTimeout(timeout);
              resolve(parsed);
              return;
            }
          } catch {}
        }
      });

      stdioChild.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    // Send JSON-RPC ping probe request
    const pingMsg = JSON.stringify({
      jsonrpc: '2.0',
      id: 8888,
      method: 'ping',
      params: {}
    }) + '\n';
    stdioChild.stdin.write(pingMsg);

    const pingResponse = await pingPromise;
    assert.strictEqual(pingResponse.jsonrpc, '2.0', 'Ping response must be JSON-RPC 2.0');
    assert.strictEqual(pingResponse.id, 8888, 'Ping response must match request id');
    assert.deepStrictEqual(pingResponse.result, {}, 'Ping response result must be empty object');
    assert.strictEqual(pingReceived, true, 'Ping response must have been received');

    // Terminate cleanly with SIGTERM
    const exitPromise = new Promise((resolve) => {
      stdioChild.on('exit', (code, signal) => {
        resolve({ code, signal });
      });
    });
    stdioChild.kill('SIGTERM');
    const exitStatus = await exitPromise;
    assert(exitStatus.code === 0 || exitStatus.signal === 'SIGTERM', 'Stdio process should terminate cleanly');

    console.log('    ✔ Section 4: Stdio proxy subprocess lifecycle & ping probe PASSED');
  }

  // =========================================================================
  // Section 5: HTTP Gateway Serve Lifecycle & Health Endpoint
  // =========================================================================
  {
    const ephemeralPort = await getFreePort();
    const serverChild = spawn('node', [CLI_PATH, 'serve', '--port', String(ephemeralPort)], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let healthOk = false;
    let serverOutput = '';

    serverChild.stdout.on('data', (chunk) => {
      serverOutput += chunk.toString();
    });

    // Poll /health endpoint until HTTP server is ready
    const pollHealth = async () => {
      for (let attempt = 0; attempt < 25; attempt++) {
        await new Promise(r => setTimeout(r, 100));
        try {
          const res = await new Promise((resolve, reject) => {
            const req = http.get(`http://127.0.0.1:${ephemeralPort}/health`, (res) => {
              let body = '';
              res.on('data', d => { body += d; });
              res.on('end', () => resolve({ statusCode: res.statusCode, body }));
            });
            req.on('error', reject);
            req.setTimeout(500, () => { req.destroy(); reject(new Error('timeout')); });
          });

          if (res.statusCode === 200) {
            const data = JSON.parse(res.body);
            if (data.status === 'healthy') {
              healthOk = true;
              return;
            }
          }
        } catch {
          // Retry on connection refused while server is starting
        }
      }
      throw new Error(`HTTP server failed to respond on port ${ephemeralPort} within 2.5s. Output: ${serverOutput}`);
    };

    await pollHealth();
    assert.strictEqual(healthOk, true, 'HTTP Gateway must respond HTTP 200 with { status: "healthy" }');

    // Terminate cleanly with SIGTERM
    const exitPromise = new Promise((resolve) => {
      serverChild.on('exit', (code, signal) => {
        resolve({ code, signal });
      });
    });
    serverChild.kill('SIGTERM');
    const exitStatus = await exitPromise;
    assert(exitStatus.code === 0 || exitStatus.signal === 'SIGTERM', 'HTTP server should terminate cleanly on SIGTERM');

    console.log('    ✔ Section 5: HTTP Gateway serve subprocess lifecycle & health check PASSED');
  }

  console.log('✅ CLI Automation: All 5 sections passed verification!\n');
}

function resPosPosVerifySafe(res) {
  return res.code === 0;
}

module.exports = { runCliTests };

if (require.main === module) {
  runCliTests().catch(err => {
    console.error('❌ CLI Tests Failed:', err);
    process.exit(1);
  });
}
