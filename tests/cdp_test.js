'use strict';

const http = require('node:http');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { AegisProxyServer } = require('../src/protocol/proxy');

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function run() {
  const PORT = 3388;
  const CHROME_DEBUG_PORT = 9222;

  // 1. Start AegisProxyServer
  const server = new AegisProxyServer({ port: PORT });
  await server.startHttp(PORT);
  console.log(`Server started on http://localhost:${PORT}`);

  // 2. Start Headless Chrome
  const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const chromeProc = spawn(chromePath, [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--user-data-dir=/tmp/aegis-cdp-profile',
    `--remote-debugging-port=${CHROME_DEBUG_PORT}`,
    '--window-size=1440,900'
  ]);

  await sleep(1000);

  try {
    // 3. Get websocket debugger URL
    const listRes = await fetch(`http://127.0.0.1:${CHROME_DEBUG_PORT}/json/list`);
    const pages = await listRes.json();
    const targetWsUrl = pages[0].webSocketDebuggerUrl;
    console.log('Connected to target WS:', targetWsUrl);

    const ws = new WebSocket(targetWsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve } = pending.get(msg.id);
        pending.delete(msg.id);
        resolve(msg.result);
      }
      if (msg.method === 'Runtime.consoleAPICalled') {
        console.log(`[BROWSER CONSOLE ${msg.params.type}]:`, ...msg.params.args.map(a => a.value || a.description));
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        console.error('[BROWSER UNCAUGHT EXCEPTION]:', msg.params.exceptionDetails);
      }
    };

    await new Promise((resolve) => ws.onopen = resolve);

    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = msgId++;
        pending.set(id, { resolve, reject });
        ws.send(JSON.stringify({ id, method, params }));
      });
    }

    // Enable domains
    await send('Runtime.enable');
    await send('Page.enable');
    await send('DOM.enable');

    // Navigate to page
    console.log('Navigating to http://localhost:' + PORT + ' ...');
    await send('Page.navigate', { url: `http://localhost:${PORT}/` });
    await sleep(2000);

    // Set standard desktop viewport
    await send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false
    });
    await sleep(500);

    // Evaluate initial UI state
    const evalResult = await send('Runtime.evaluate', {
      expression: `
        (() => {
          return {
            title: document.title,
            ledgerChainLength: window.aegisStudio ? window.aegisStudio.ledger.chain.length : 'no app',
            activeTab: document.querySelector('.nav-tab.active')?.dataset?.tab,
            statsEvaluated: document.getElementById('stat-total-evals')?.textContent,
            errorsCount: window.__errors ? window.__errors.length : 0
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Page initial state:', evalResult.result.value);

    // Capture screenshot of Cockpit
    const screenshot1 = await send('Page.captureScreenshot', { format: 'png' });
    const fs = require('node:fs');
    fs.writeFileSync('tests/screenshot_cockpit.png', Buffer.from(screenshot1.data, 'base64'));
    console.log('Saved tests/screenshot_cockpit.png');

    // Test clicking tabs and taking screenshots
    const tabs = ['tab-tools', 'tab-firewall', 'tab-fuzzer', 'tab-exploits', 'tab-pipeline', 'tab-ledger', 'tab-forensics', 'tab-synthesizer', 'tab-configs', 'tab-servers'];
    for (const tab of tabs) {
      await send('Runtime.evaluate', {
        expression: `document.querySelector('.nav-tab[data-tab="${tab}"]')?.click();`
      });
      await sleep(300);
      const ss = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(`tests/screenshot_${tab}.png`, Buffer.from(ss.data, 'base64'));
      console.log(`Tab ${tab} clicked & screenshot saved.`);
    }

    // Test Quick Scenarios buttons
    console.log('Testing Quick Scenarios buttons...');
    const scenarioBtns = [
      'scenario-injection-btn',
      'scenario-exploit-btn',
      'scenario-pipeline-btn',
      'scenario-fuzz-btn',
      'scenario-tamper-btn',
      'scenario-forensics-btn',
      'scenario-configs-btn'
    ];
    for (const btnId of scenarioBtns) {
      const clickRes = await send('Runtime.evaluate', {
        expression: `
          (() => {
            const btn = document.getElementById('${btnId}');
            if (!btn) return 'BUTTON NOT FOUND: ${btnId}';
            btn.click();
            return 'OK: ' + btn.textContent.trim();
          })()
        `,
        returnByValue: true
      });
      console.log(`Scenario button ${btnId}:`, clickRes.result.value);
      await sleep(500);
    }

    // Test Tool Execution
    console.log('Testing Tool Execution in Tool Studio...');
    await send('Runtime.evaluate', { expression: `document.querySelector('.nav-tab[data-tab="tab-tools"]')?.click();` });
    await sleep(300);
    const execRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const btn = document.getElementById('execute-tool-btn');
          if (!btn) return 'NO EXEC BTN';
          btn.click();
          return 'CLICKED EXEC';
        })()
      `,
      returnByValue: true
    });
    console.log('Execute Tool clicked:', execRes.result.value);
    await sleep(500);
    const outputRes = await send('Runtime.evaluate', {
      expression: `document.getElementById('tool-result-display')?.textContent`,
      returnByValue: true
    });
    console.log('Tool execution result preview:', outputRes.result.value?.slice(0, 100));

    // Test Tool Search Filter
    console.log('Testing Tool Search Filter...');
    const searchRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const input = document.getElementById('tool-search-input');
          if (!input) return 'NO SEARCH INPUT';
          input.value = 'hash';
          input.dispatchEvent(new Event('input'));
          const visible = Array.from(document.querySelectorAll('.tool-item')).filter(el => el.style.display !== 'none');
          return { visibleCount: visible.length, names: visible.map(v => v.querySelector('.tool-name')?.textContent) };
        })()
      `,
      returnByValue: true
    });
    console.log('Tool search filter result:', searchRes.result.value);

    // Test Fuzzer Launch
    console.log('Testing Fuzzer Launch...');
    await send('Runtime.evaluate', { expression: `document.querySelector('.nav-tab[data-tab="tab-fuzzer"]')?.click();` });
    await sleep(300);
    const fuzzRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const btn = document.getElementById('start-fuzz-btn');
          if (!btn) return 'NO FUZZ BTN';
          btn.click();
          return 'CLICKED START FUZZ';
        })()
      `,
      returnByValue: true
    });
    console.log('Start Fuzz clicked:', fuzzRes.result.value);
    await sleep(1500); // wait for fuzz run
    const fuzzScorecard = await send('Runtime.evaluate', {
      expression: `
        (() => {
          return {
            containerDisplay: document.getElementById('fuzzer-scorecard-container')?.style.display,
            grade: document.getElementById('scorecard-grade')?.textContent,
            title: document.getElementById('scorecard-title')?.textContent,
            rowCount: document.querySelectorAll('#fuzz-results-body tr').length
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Fuzzer outcome:', fuzzScorecard.result.value);

    // Test Exploit Studio Launch
    console.log('Testing Exploit Studio...');
    await send('Runtime.evaluate', { expression: `document.querySelector('.nav-tab[data-tab="tab-exploits"]')?.click();` });
    await sleep(300);
    const exploitRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const btn = document.getElementById('run-exploit-audit-btn');
          if (!btn) return 'NO EXPLOIT BTN';
          btn.click();
          return 'CLICKED EXPLOIT AUDIT';
        })()
      `,
      returnByValue: true
    });
    console.log('Run exploit audit clicked:', exploitRes.result.value);
    await sleep(1000);
    const exploitOutcome = await send('Runtime.evaluate', {
      expression: `
        (() => {
          return {
            grade: document.getElementById('exploit-grade-display')?.textContent,
            score: document.getElementById('exploit-score-pct')?.textContent,
            total: document.getElementById('exploit-total-count')?.textContent,
            defended: document.getElementById('exploit-defended-count')?.textContent,
            vulnerable: document.getElementById('exploit-vulnerable-count')?.textContent,
            rowCount: document.querySelectorAll('#exploit-results-body tr').length
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Exploit outcome:', exploitOutcome.result.value);

    // Test DAG Execution
    console.log('Testing DAG execution...');
    await send('Runtime.evaluate', { expression: `document.querySelector('.nav-tab[data-tab="tab-pipeline"]')?.click();` });
    await sleep(300);
    const dagRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const btn = document.getElementById('run-pipeline-btn');
          if (!btn) return 'NO DAG BTN';
          btn.click();
          return 'CLICKED DAG RUN';
        })()
      `,
      returnByValue: true
    });
    console.log('Run DAG clicked:', dagRes.result.value);
    await sleep(1800);
    const dagOutcome = await send('Runtime.evaluate', {
      expression: `
        (() => {
          return {
            statusBadge: document.getElementById('pipeline-status-badge')?.textContent,
            logLines: document.querySelectorAll('.pipeline-log-entry').length
          };
        })()
      `,
      returnByValue: true
    });
    console.log('DAG outcome:', dagOutcome.result.value);
    assert.strictEqual(dagOutcome.result.value.statusBadge, 'COMPLETED', 'DAG pipeline must reach COMPLETED status');

    // Check responsive widths (1024px, 768px, 480px)
    console.log('Testing responsive viewports...');
    for (const width of [1024, 768, 480]) {
      await send('Emulation.setDeviceMetricsOverride', {
        width,
        height: 800,
        deviceScaleFactor: 1,
        mobile: width <= 768
      });
      await sleep(300);
      const ssResp = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(`tests/screenshot_resp_${width}.png`, Buffer.from(ssResp.data, 'base64'));
      console.log(`Saved screenshot for viewport width ${width}px`);
    }

    // Test mobile drawer toggle on 480px
    console.log('Testing mobile drawer toggle on 480px...');
    await send('Emulation.setDeviceMetricsOverride', { width: 480, height: 800, deviceScaleFactor: 1, mobile: true });
    await sleep(300);
    await send('Runtime.evaluate', { expression: `document.getElementById('mobile-menu-btn').click();` });
    await sleep(100);
    const drawerOpenRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const sidebar = document.querySelector('.aegis-sidebar');
          const backdrop = document.getElementById('sidebar-backdrop');
          const style = window.getComputedStyle(sidebar);
          const rect = sidebar.getBoundingClientRect();
          return {
            opened: sidebar.classList.contains('mobile-open'),
            className: sidebar.className,
            transform: style.transform,
            left: style.left,
            width: style.width,
            rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height }
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Drawer after click:', JSON.stringify(drawerOpenRes.result.value, null, 2));
    assert.strictEqual(drawerOpenRes.result.value.opened, true, 'Drawer must have mobile-open class');
    assert.strictEqual(drawerOpenRes.result.value.rect.x, 0, 'Drawer rect.x must be 0 when open');
    const ssDrawer = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('tests/screenshot_mobile_drawer.png', Buffer.from(ssDrawer.data, 'base64'));

    // Click backdrop to close
    const drawerCloseRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const backdrop = document.getElementById('sidebar-backdrop');
          backdrop.click();
          const sidebar = document.querySelector('.aegis-sidebar');
          return { closed: !sidebar.classList.contains('mobile-open') };
        })()
      `,
      returnByValue: true
    });
    console.log('Drawer closed via backdrop?', drawerCloseRes.result.value);
    assert.strictEqual(drawerCloseRes.result.value.closed, true, 'Drawer must close when backdrop clicked');

    ws.close();
  } finally {
    chromeProc.kill('SIGKILL');
    server.stop();
  }
}

run().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
