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

    // Return to desktop viewport
    await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
    await sleep(300);

    // ==============================================================
    // Test Feature 1: Command Palette (Cmd+K / Ctrl+K)
    // ==============================================================
    console.log('Testing Command Palette modal & navigation...');

    // 1. Test opening via global Cmd+K / Ctrl+K keyboard shortcut
    const shortcutOpen = await send('Runtime.evaluate', {
      expression: `
        (() => {
          window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true }));
          const backdrop = document.getElementById('command-palette-backdrop');
          const input = document.getElementById('palette-search-input');
          return {
            open: backdrop && backdrop.style.display === 'flex',
            hasInput: !!input,
            commandsCount: document.querySelectorAll('.palette-item').length
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Palette shortcut open state:', shortcutOpen.result.value);
    assert.strictEqual(shortcutOpen.result.value.open, true, 'Command palette must open via Cmd+K shortcut');
    assert(shortcutOpen.result.value.commandsCount >= 20, 'Command palette must render >= 20 commands');

    // 2. Test XSS Immunity in Palette Search Input
    const xssTest = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const input = document.getElementById('palette-search-input');
          input.value = '<img src="x" onerror="window.__xssPwned=1">';
          input.dispatchEvent(new Event('input'));
          const emptyDiv = document.querySelector('.palette-empty');
          return {
            xssPwned: !!window.__xssPwned,
            htmlContent: emptyDiv ? emptyDiv.innerHTML : '',
            escaped: emptyDiv ? emptyDiv.innerHTML.includes('&lt;img') : false
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Palette XSS immunity check:', xssTest.result.value);
    assert.strictEqual(xssTest.result.value.xssPwned, false, 'XSS must not execute from search input');
    assert.strictEqual(xssTest.result.value.escaped, true, 'HTML tags in search input must be escaped');

    // Screenshot open palette
    await sleep(300);
    const ssPalette = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('tests/screenshot_command_palette.png', Buffer.from(ssPalette.data, 'base64'));
    console.log('Saved tests/screenshot_command_palette.png');

    // 3. Test Keyboard Navigation (ArrowDown, ArrowUp, Enter) to switch tab
    const paletteNav = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const input = document.getElementById('palette-search-input');
          input.value = 'fuzzer';
          input.dispatchEvent(new Event('input'));

          // Press ArrowDown to navigate to first result, then Enter
          input.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
          input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));

          const backdrop = document.getElementById('command-palette-backdrop');
          return {
            closed: backdrop.style.display === 'none',
            activeTab: document.querySelector('.nav-tab.active')?.getAttribute('data-tab')
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Palette keyboard navigation result:', paletteNav.result.value);
    assert.strictEqual(paletteNav.result.value.closed, true, 'Palette must close after Enter key selection');
    assert.strictEqual(paletteNav.result.value.activeTab, 'tab-fuzzer', 'Tab must switch to fuzzer target via keyboard');

    // 4. Test Firewall Mode switching from Command Palette
    const modeSwitchRes = await send('Runtime.evaluate', {
      expression: `
        (() => {
          window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true }));
          const input = document.getElementById('palette-search-input');
          input.value = 'Set Firewall Mode: AUDIT_ONLY';
          input.dispatchEvent(new Event('input'));
          input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));

          const checkedRadio = document.querySelector('input[name="firewall-mode"]:checked');
          const badge = document.getElementById('current-mode-badge');
          return {
            modeValue: checkedRadio ? checkedRadio.value : null,
            badgeText: badge ? badge.textContent.trim() : null
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Palette mode switch result:', modeSwitchRes.result.value);
    assert.strictEqual(modeSwitchRes.result.value.modeValue, 'AUDIT_ONLY', 'Palette must switch mode to AUDIT_ONLY');

    // ==============================================================
    // Test Feature 2: Interactive Threat Log Filter Tags
    // ==============================================================
    console.log('Testing Interactive Threat Log Filter Tags in Cockpit...');
    await send('Runtime.evaluate', { expression: `document.querySelector('.nav-tab[data-tab="tab-dashboard"]')?.click();` });
    await sleep(200);

    // Trigger scenario to generate initial threat events
    await send('Runtime.evaluate', { expression: `document.getElementById('scenario-injection-btn')?.click();` });
    await sleep(200);

    const filterTestResult = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const tagAll = document.getElementById('filter-pill-all');
          const tagBlock = document.getElementById('filter-pill-block');
          const tagClean = document.getElementById('filter-pill-success');
          const chipSec1 = document.querySelector('.filter-chip[data-rule="SEC-001"]');
          const resetBtn = document.getElementById('filter-pill-reset');

          // Initial counts
          const countAll = parseInt(document.getElementById('filter-count-all')?.textContent || '0', 10);
          const countBlock = parseInt(document.getElementById('filter-count-block')?.textContent || '0', 10);

          // Click Blocked Threats filter
          tagBlock.click();
          const items = Array.from(document.querySelectorAll('#event-stream-container .event-item'));
          const visibleAfterBlock = items.filter(el => !el.classList.contains('filter-hidden')).length;

          // Now click Clean, then click SEC-001 chip (verifies no cross-filter conflict)
          tagClean.click();
          chipSec1.click();
          const visibleAfterSec1FromClean = items.filter(el => !el.classList.contains('filter-hidden')).length;

          // Untoggle SEC-001 chip
          chipSec1.click();
          const visibleAfterUntoggle = items.filter(el => !el.classList.contains('filter-hidden')).length;

          // Click Reset
          resetBtn.click();
          const visibleAfterReset = items.filter(el => !el.classList.contains('filter-hidden')).length;

          return {
            countAll,
            countBlock,
            visibleAfterBlock,
            visibleAfterSec1FromClean,
            visibleAfterUntoggle,
            visibleAfterReset,
            allPillActiveAfterReset: tagAll.classList.contains('active')
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Threat filter test result:', filterTestResult.result.value);
    assert(filterTestResult.result.value.countAll > 0, 'Must have events in stream');
    assert(filterTestResult.result.value.visibleAfterSec1FromClean > 0, 'SEC-001 chip must show events even after Clean pill clicked');
    assert.strictEqual(filterTestResult.result.value.allPillActiveAfterReset, true, 'All pill must be active after reset');

    // Test Empty State Ghost Message Clearing on New Matching Event
    const emptyStateTest = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const chipSec9 = document.querySelector('.filter-chip[data-rule="SEC-009"]');
          chipSec9.click();
          const emptyMsgBefore = document.getElementById('event-stream-empty-msg');
          const emptyVisibleBefore = emptyMsgBefore && emptyMsgBefore.style.display !== 'none';

          // Now log an event matching SEC-009
          window.aegis.logEvent('FIREWALL_BLOCK', 'Blocked /app/.env exfiltration', 'block', { ruleId: 'SEC-009' });
          const emptyMsgAfter = document.getElementById('event-stream-empty-msg');
          const emptyVisibleAfter = emptyMsgAfter && emptyMsgAfter.style.display !== 'none';

          // Reset filter
          document.getElementById('filter-pill-reset').click();

          return {
            emptyVisibleBefore,
            emptyVisibleAfter
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Empty state clearing check:', emptyStateTest.result.value);
    assert.strictEqual(emptyStateTest.result.value.emptyVisibleBefore, true, 'Empty message must be visible before matching event');
    assert.strictEqual(emptyStateTest.result.value.emptyVisibleAfter, false, 'Empty message must automatically disappear when matching event arrives');

    const ssFilter = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('tests/screenshot_threat_filters.png', Buffer.from(ssFilter.data, 'base64'));
    console.log('Saved tests/screenshot_threat_filters.png');

    // ==============================================================
    // Test Feature 3: Sound Effect Volume Controls
    // ==============================================================
    console.log('Testing Sound Effect Volume Controls & Popover...');
    const soundTestResult = await send('Runtime.evaluate', {
      expression: `
        (() => {
          const soundBtn = document.getElementById('sound-toggle-btn');
          const popover = document.getElementById('sound-popover');
          const slider = document.getElementById('sound-volume-slider');
          const badge = document.getElementById('sound-vol-badge');
          const muteIconBtn = document.getElementById('sound-mute-icon-btn');
          const preset25 = document.querySelector('.sound-preset-chip[data-volume="25"]');
          const testBtn = document.getElementById('sound-test-btn');

          // Open popover
          soundBtn.click();
          const popoverVisible = popover && popover.style.display === 'flex';

          // Set slider to 75%
          slider.value = '75';
          slider.dispatchEvent(new Event('input'));
          const badgeAt75 = badge.textContent.trim();

          // Click 25% preset
          preset25.click();
          const badgeAt25 = badge.textContent.trim();

          // Click mute icon toggle
          muteIconBtn.click();
          const badgeMuted = badge.textContent.trim();

          // Click unmute
          muteIconBtn.click();
          const badgeUnmuted = badge.textContent.trim();

          // Click test chime
          testBtn.click();

          // Test closing popover via Escape key
          document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
          const popoverClosedViaEscape = popover.style.display === 'none';

          return {
            popoverVisible,
            badgeAt75,
            badgeAt25,
            badgeMuted,
            badgeUnmuted,
            popoverClosedViaEscape,
            finalVolume: window.aegis ? window.aegis.sound.volume : null
          };
        })()
      `,
      returnByValue: true
    });
    console.log('Sound volume test result:', soundTestResult.result.value);
    assert.strictEqual(soundTestResult.result.value.popoverVisible, true, 'Sound popover must open on button click');
    assert.strictEqual(soundTestResult.result.value.badgeAt75, '75%', 'Volume badge must reflect slider input');
    assert.strictEqual(soundTestResult.result.value.badgeAt25, '25%', 'Volume badge must reflect preset chip click');
    assert.strictEqual(soundTestResult.result.value.badgeMuted, 'MUTE', 'Volume badge must show MUTE when muted');
    assert.strictEqual(soundTestResult.result.value.badgeUnmuted, '25%', 'Volume badge must restore to 25% when unmuted');
    assert.strictEqual(soundTestResult.result.value.popoverClosedViaEscape, true, 'Sound popover must close on Escape key');
    assert.strictEqual(soundTestResult.result.value.finalVolume, 0.25, 'SoundEngine volume must be 0.25');

    const ssSound = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('tests/screenshot_sound_controls.png', Buffer.from(ssSound.data, 'base64'));
    console.log('Saved tests/screenshot_sound_controls.png');

    console.log('✅ All CDP browser tests passed successfully!');
    process.exit(0);
  } finally {
    chromeProc.kill('SIGKILL');
    server.stop();
  }
}

run().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
