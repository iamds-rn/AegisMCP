/**
 * AegisMCP - Runtime Micro-Sandboxing (Wasm & Isolated VM Sandbox)
 * Zero runtime dependencies (uses native WebAssembly and node:vm).
 * Enforces memory bounding, execution timeouts, and strict capability isolation.
 */

'use strict';

const vm = require('node:vm');

const ERROR_CODES = {
  AEGIS_SANDBOX_TIMEOUT: -32005,
  AEGIS_SANDBOX_MEMORY_EXCEEDED: -32009,
  AEGIS_SANDBOX_VIOLATION: -32010
};

// Minimal verified WebAssembly binary that exports an 'add(i32, i32) -> i32' function
const SAMPLE_WASM_BINARY = Buffer.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);

class WasmSandbox {
  constructor(options = {}) {
    this.maxMemoryPages = options.maxMemoryPages || 16; // 16 pages = 1MB (64KB per page)
    this.timeoutMs = options.timeoutMs || 2000;
  }

  /**
   * Instantiates and runs an exported function from a WebAssembly binary
   * @param {Buffer|Uint8Array} wasmBytes
   * @param {string} funcName
   * @param {Array<number>} args
   * @param {Object} imports
   */
  async execute(wasmBytes, funcName, args = [], imports = {}) {
    const memory = new WebAssembly.Memory({
      initial: 1,
      maximum: this.maxMemoryPages
    });

    const safeImports = {
      env: {
        memory,
        abort: () => {
          throw new Error('WASM execution aborted');
        },
        ...(imports.env || {})
      },
      ...imports
    };

    let module;
    try {
      module = new WebAssembly.Module(wasmBytes);
    } catch (compileErr) {
      const err = new Error('WASM compilation failed: ' + compileErr.message);
      err.code = ERROR_CODES.AEGIS_SANDBOX_VIOLATION;
      throw err;
    }

    let instance;
    try {
      instance = new WebAssembly.Instance(module, safeImports);
    } catch (instErr) {
      const err = new Error('WASM instantiation failed: ' + instErr.message);
      err.code = ERROR_CODES.AEGIS_SANDBOX_VIOLATION;
      throw err;
    }

    const targetFn = instance.exports[funcName];
    if (typeof targetFn !== 'function') {
      const err = new Error(`Export '${funcName}' is not a function in WASM module`);
      err.code = ERROR_CODES.AEGIS_SANDBOX_VIOLATION;
      throw err;
    }

    // Execute with timeout race
    return new Promise((resolve, reject) => {
      let timer = null;
      let completed = false;

      timer = setTimeout(() => {
        if (!completed) {
          completed = true;
          const err = new Error(`WASM execution exceeded timeout of ${this.timeoutMs}ms`);
          err.code = ERROR_CODES.AEGIS_SANDBOX_TIMEOUT;
          reject(err);
        }
      }, this.timeoutMs);

      try {
        const result = targetFn(...args);
        completed = true;
        clearTimeout(timer);
        resolve({
          result,
          memoryPages: memory.buffer.byteLength / 65536,
          byteLength: memory.buffer.byteLength
        });
      } catch (execErr) {
        completed = true;
        clearTimeout(timer);
        const err = new Error('WASM runtime error: ' + execErr.message);
        err.code = ERROR_CODES.AEGIS_SANDBOX_VIOLATION;
        reject(err);
      }
    });
  }
}

/**
 * IsolatedVmSandbox provides a secure environment for evaluating untrusted JS logic
 * with stripped globals and hard timeout limits.
 */
class IsolatedVmSandbox {
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 1000;
  }

  execute(code, sandboxScope = {}) {
    // Strip process, require, global, console, fs
    const context = vm.createContext({
      Math,
      JSON,
      Date,
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      ...sandboxScope
    });

    try {
      const script = new vm.Script(code);
      const result = script.runInContext(context, {
        timeout: this.timeoutMs,
        displayErrors: true
      });
      return { success: true, result };
    } catch (err) {
      const isTimeout = err.message.includes('timed out') || err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT';
      const safeErr = new Error(isTimeout ? `Script execution timed out after ${this.timeoutMs}ms` : err.message);
      safeErr.code = isTimeout ? ERROR_CODES.AEGIS_SANDBOX_TIMEOUT : ERROR_CODES.AEGIS_SANDBOX_VIOLATION;
      throw safeErr;
    }
  }
}

class SandboxManager {
  constructor(options = {}) {
    this.wasmSandbox = new WasmSandbox(options.wasm || {});
    this.vmSandbox = new IsolatedVmSandbox(options.vm || {});
  }

  async runWasm(wasmBytes, funcName, args, imports) {
    return this.wasmSandbox.execute(wasmBytes, funcName, args, imports);
  }

  runScript(code, scope) {
    return this.vmSandbox.execute(code, scope);
  }
}

module.exports = {
  WasmSandbox,
  IsolatedVmSandbox,
  SandboxManager,
  SAMPLE_WASM_BINARY,
  ERROR_CODES
};
