/**
 * AegisMCP - Cryptographic Audit Ledger File Persistence
 *
 * Implements crash-resilient, append-only streaming JSONL persistence for AuditBlock records.
 * Features:
 * 1. Append-only streaming JSONL persistence for AuditBlock records.
 * 2. Line-by-line stream reading & deserialization.
 * 3. Strict cryptographic re-verification of hash chain continuity:
 *    H_i = SHA-256(i || t || H_{i-1} || canonicalEvent)
 * 4. Full reconstruction of AuditLedger state from disk.
 * 5. Atomic sync support:
 *    - Direct synchronous append (fs.appendFileSync / fs.writeSync + fs.fsyncSync)
 *    - Buffered flush with atomic fsync barrier to prevent partial write corruption.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { AuditBlock, AuditLedger, GENESIS_PREV_HASH } = require('./auditLedger');

const DEFAULT_GENESIS_PREV_HASH = GENESIS_PREV_HASH || '0000000000000000000000000000000000000000000000000000000000000000';

class LedgerPersistenceError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'LedgerPersistenceError';
    this.details = details;
    this.brokenIndex = details.brokenIndex !== undefined ? details.brokenIndex : -1;
    this.lineNum = details.lineNum !== undefined ? details.lineNum : null;
    this.code = details.code || 'ERR_LEDGER_PERSISTENCE';
  }
}

class AuditFilePersistence {
  /**
   * @param {string} filePath - Absolute or relative path to .jsonl file
   * @param {Object} [options]
   * @param {boolean} [options.atomicSync=true] - Ensure immediate synchronous flush
   * @param {boolean} [options.fsync=true] - Call fsyncSync to ensure physical media durability
   * @param {boolean} [options.buffered=false] - Batch writes until bufferSize or flush()
   * @param {number} [options.bufferSize=10] - Number of lines to buffer before auto-flush
   */
  constructor(filePath, options = {}) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('filePath is required and must be a valid path string');
    }

    this.filePath = path.resolve(filePath);
    this.atomicSync = options.atomicSync !== false;
    this.fsync = options.fsync !== undefined ? options.fsync === true : this.atomicSync;
    this.buffered = options.buffered === true;
    this.bufferSize = typeof options.bufferSize === 'number' && options.bufferSize > 0
      ? options.bufferSize
      : 10;
    this.writeBuffer = [];
    this.ledger = null;

    // Ensure parent directory exists
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Serializes an AuditBlock to a canonical single-line JSON string without embedded newlines.
   * @param {AuditBlock} block
   * @returns {string} JSON line
   */
  serializeBlock(block) {
    if (!block || typeof block !== 'object') {
      throw new LedgerPersistenceError('Cannot serialize invalid block: expected object');
    }

    return JSON.stringify({
      index: block.index,
      timestamp: block.timestamp,
      prevHash: block.prevHash,
      event: block.event,
      hash: block.hash
    });
  }

  /**
   * Deserializes and validates schema of a single JSON line into an AuditBlock instance.
   * Strips UTF-8 BOM if present on initial lines.
   * @param {string} line
   * @param {number} [lineNum=1]
   * @returns {AuditBlock}
   */
  deserializeBlock(line, lineNum = 1) {
    let cleanLine = line;
    if (typeof cleanLine === 'string' && cleanLine.charCodeAt(0) === 0xFEFF) {
      cleanLine = cleanLine.slice(1);
    }

    let parsed;
    try {
      parsed = JSON.parse(cleanLine);
    } catch (err) {
      throw new LedgerPersistenceError(
        `Corrupted JSON record at line ${lineNum}: ${err.message}`,
        { lineNum, rawLine: line, code: 'ERR_MALFORMED_JSON' }
      );
    }

    if (
      typeof parsed.index !== 'number' ||
      typeof parsed.timestamp !== 'string' ||
      typeof parsed.prevHash !== 'string' ||
      !parsed.event ||
      typeof parsed.event !== 'object' ||
      typeof parsed.hash !== 'string'
    ) {
      throw new LedgerPersistenceError(
        `Malformed AuditBlock schema at line ${lineNum}`,
        { lineNum, parsed, code: 'ERR_INVALID_SCHEMA' }
      );
    }

    return new AuditBlock(
      parsed.index,
      parsed.timestamp,
      parsed.prevHash,
      parsed.event,
      parsed.hash
    );
  }

  /**
   * Appends an AuditBlock to the persistent JSONL file.
   * Validates internal payload integrity prior to writing to prevent storage poisoning.
   * In atomic mode, performs immediate sync (write + fsync) to prevent partial write corruption.
   * In buffered mode, accumulates in memory until bufferSize or explicit flush().
   * @param {AuditBlock} block
   */
  appendBlock(block) {
    if (!block || typeof block !== 'object') {
      throw new LedgerPersistenceError('Cannot append invalid block: expected object', {
        code: 'ERR_INVALID_BLOCK'
      });
    }

    // Verify block hash integrity before persisting to disk
    if (
      typeof block.index === 'number' &&
      typeof block.timestamp === 'string' &&
      typeof block.prevHash === 'string' &&
      block.event !== undefined
    ) {
      const computedHash = AuditBlock.calculateHash(block.index, block.timestamp, block.prevHash, block.event);
      if (computedHash !== block.hash) {
        throw new LedgerPersistenceError(
          `Refusing to persist corrupted block #${block.index}: payload hash mismatch`,
          {
            brokenIndex: block.index,
            expectedHash: computedHash,
            actualHash: block.hash,
            code: 'ERR_HASH_MISMATCH'
          }
        );
      }
    }

    const line = this.serializeBlock(block) + '\n';

    if (this.buffered) {
      this.writeBuffer.push(line);
      if (this.writeBuffer.length >= this.bufferSize) {
        this.flush();
      }
      return;
    }

    this._writeSync(line);
  }

  /**
   * Internal helper for atomic write + optional fsync.
   * Ensures previous line ends with newline delimiter before appending.
   * @private
   */
  _writeSync(data) {
    let payload = data;
    if (fs.existsSync(this.filePath)) {
      const stat = fs.statSync(this.filePath);
      if (stat.size > 0) {
        const fdRead = fs.openSync(this.filePath, 'r');
        try {
          const buf = Buffer.alloc(1);
          fs.readSync(fdRead, buf, 0, 1, stat.size - 1);
          if (buf[0] !== 0x0A) {
            payload = '\n' + payload;
          }
        } finally {
          fs.closeSync(fdRead);
        }
      }
    }

    if (this.fsync) {
      const fd = fs.openSync(this.filePath, 'a');
      try {
        fs.writeSync(fd, payload, null, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    } else {
      fs.appendFileSync(this.filePath, payload, 'utf8');
    }
  }

  /**
   * Flushes all buffered writes to disk with fsync barrier.
   * Preserves buffer if write encounters I/O error to avoid data loss.
   */
  flush() {
    if (this.writeBuffer.length === 0) return;
    const data = this.writeBuffer.join('');
    this._writeSync(data);
    this.writeBuffer = [];
  }

  /**
   * Reads the persistent JSONL file line-by-line, cryptographically verifies
   * sequential hash chain continuity:
   *   H_0 = SHA-256(0 || t || GENESIS_PREV_HASH || canonicalEvent)
   *   H_i = SHA-256(i || t || H_{i-1} || canonicalEvent)
   * and returns reconstructed AuditBlock records.
   *
   * @param {Object} [options]
   * @param {boolean} [options.allowEmpty=false]
   * @param {boolean} [options.allowMissing=false]
   * @returns {AuditBlock[]} Array of verified AuditBlock instances
   */
  recoverBlocks(options = {}) {
    if (!fs.existsSync(this.filePath)) {
      if (options.allowMissing) return [];
      throw new LedgerPersistenceError(`Persistence file not found: ${this.filePath}`, {
        code: 'ERR_FILE_NOT_FOUND'
      });
    }

    const content = fs.readFileSync(this.filePath, 'utf8');
    if (!content || content.trim().length === 0) {
      if (options.allowEmpty) return [];
      throw new LedgerPersistenceError('Ledger persistence file is empty (missing genesis block)', {
        code: 'ERR_EMPTY_LEDGER'
      });
    }

    const lines = content.split('\n');
    const blocks = [];
    let prevBlock = null;
    let lineNum = 0;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      // Skip trailing empty line or blank lines
      if (rawLine.trim() === '') {
        continue;
      }

      lineNum++;
      const block = this.deserializeBlock(rawLine, lineNum);

      if (prevBlock === null) {
        // Genesis block verification
        if (block.index !== 0) {
          throw new LedgerPersistenceError(
            `Corrupted genesis block at line ${lineNum}: expected index 0, got ${block.index}`,
            { lineNum, brokenIndex: block.index, code: 'ERR_INVALID_GENESIS_INDEX' }
          );
        }
        if (block.prevHash !== DEFAULT_GENESIS_PREV_HASH) {
          throw new LedgerPersistenceError(
            `Corrupted genesis block at line ${lineNum}: prevHash must be genesis zero hash`,
            { lineNum, brokenIndex: 0, code: 'ERR_INVALID_GENESIS_PREV_HASH' }
          );
        }
        const computedHash = AuditBlock.calculateHash(
          block.index,
          block.timestamp,
          block.prevHash,
          block.event
        );
        if (block.hash !== computedHash) {
          throw new LedgerPersistenceError(
            `Cryptographic tampering detected! Genesis block hash corrupted at line ${lineNum}`,
            {
              lineNum,
              brokenIndex: 0,
              expectedHash: computedHash,
              actualHash: block.hash,
              code: 'ERR_HASH_MISMATCH'
            }
          );
        }
      } else {
        // Sequential link verification
        if (block.index !== prevBlock.index + 1) {
          throw new LedgerPersistenceError(
            `Broken index sequence at block #${block.index} (line ${lineNum}): expected ${prevBlock.index + 1}`,
            {
              lineNum,
              brokenIndex: block.index,
              expectedIndex: prevBlock.index + 1,
              code: 'ERR_SEQUENCE_GAP'
            }
          );
        }

        if (block.prevHash !== prevBlock.hash) {
          throw new LedgerPersistenceError(
            `Hash pointer mismatch at block #${block.index} (line ${lineNum}): does not match prev block hash`,
            {
              lineNum,
              brokenIndex: block.index,
              expectedPrevHash: prevBlock.hash,
              actualPrevHash: block.prevHash,
              code: 'ERR_PREV_HASH_MISMATCH'
            }
          );
        }

        const computedHash = AuditBlock.calculateHash(
          block.index,
          block.timestamp,
          block.prevHash,
          block.event
        );
        if (block.hash !== computedHash) {
          throw new LedgerPersistenceError(
            `Cryptographic tampering detected! Block #${block.index} hash corrupted (line ${lineNum})`,
            {
              lineNum,
              brokenIndex: block.index,
              expectedHash: computedHash,
              actualHash: block.hash,
              code: 'ERR_HASH_MISMATCH'
            }
          );
        }
      }

      blocks.push(block);
      prevBlock = block;
    }

    if (blocks.length === 0) {
      if (options.allowEmpty) return [];
      throw new LedgerPersistenceError('No valid audit blocks found in persistence file', {
        code: 'ERR_EMPTY_LEDGER'
      });
    }

    return blocks;
  }

  /**
   * Reconstructs an AuditLedger instance from the persistent JSONL file.
   * If the file does not exist and createIfMissing is true, creates a new ledger,
   * writes its genesis block, and returns the ledger.
   *
   * @param {Object} [options]
   * @param {boolean} [options.createIfMissing=false]
   * @param {number} [options.maxMemoryBlocks=5000]
   * @returns {AuditLedger} Reconstructed AuditLedger with verified chain state
   */
  recoverLedger(options = {}) {
    const fileExists = fs.existsSync(this.filePath);
    const isEmpty = fileExists && fs.statSync(this.filePath).size === 0;

    if (!fileExists || isEmpty) {
      if (options.createIfMissing) {
        const ledger = new AuditLedger(options);
        ledger.persistence = this;
        this.ledger = ledger;
        this.appendBlock(ledger.chain[0]);
        return ledger;
      }
    }

    const blocks = this.recoverBlocks(options);
    const maxMemoryBlocks = options.maxMemoryBlocks || 5000;
    const ledger = new AuditLedger({ maxMemoryBlocks });

    if (blocks.length <= maxMemoryBlocks) {
      ledger.chain = blocks;
      ledger.archivedBlocks = [];
    } else {
      ledger.archivedBlocks = blocks.slice(0, blocks.length - maxMemoryBlocks);
      ledger.chain = blocks.slice(-maxMemoryBlocks);
    }

    ledger.persistence = this;
    this.ledger = ledger;

    return ledger;
  }

  /**
   * Async generator that streams AuditBlocks line-by-line from disk,
   * validating hash chain continuity incrementally.
   */
  async *streamBlocks() {
    if (!fs.existsSync(this.filePath)) {
      throw new LedgerPersistenceError(`Persistence file not found: ${this.filePath}`, {
        code: 'ERR_FILE_NOT_FOUND'
      });
    }

    const fileStream = fs.createReadStream(this.filePath, { encoding: 'utf8' });
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    let prevBlock = null;
    let lineNum = 0;

    for await (const rawLine of rl) {
      if (rawLine.trim() === '') continue;
      lineNum++;
      const block = this.deserializeBlock(rawLine, lineNum);

      if (prevBlock === null) {
        if (block.index !== 0 || block.prevHash !== DEFAULT_GENESIS_PREV_HASH) {
          throw new LedgerPersistenceError(`Corrupted genesis block at line ${lineNum}`, {
            lineNum,
            brokenIndex: 0
          });
        }
        const computed = AuditBlock.calculateHash(0, block.timestamp, block.prevHash, block.event);
        if (block.hash !== computed) {
          throw new LedgerPersistenceError(`Genesis hash mismatch at line ${lineNum}`, {
            lineNum,
            brokenIndex: 0
          });
        }
      } else {
        if (block.index !== prevBlock.index + 1) {
          throw new LedgerPersistenceError(`Sequence gap at block #${block.index}`, {
            lineNum,
            brokenIndex: block.index
          });
        }
        if (block.prevHash !== prevBlock.hash) {
          throw new LedgerPersistenceError(`Hash pointer mismatch at block #${block.index}`, {
            lineNum,
            brokenIndex: block.index
          });
        }
        const computed = AuditBlock.calculateHash(block.index, block.timestamp, block.prevHash, block.event);
        if (block.hash !== computed) {
          throw new LedgerPersistenceError(`Hash mismatch at block #${block.index}`, {
            lineNum,
            brokenIndex: block.index
          });
        }
      }

      prevBlock = block;
      yield block;
    }
  }

  /**
   * Diagnostic verification of the persistence file without altering state.
   * @returns {{ valid: boolean, blockCount?: number, headHash?: string, genesisHash?: string, error?: string, brokenIndex?: number }}
   */
  verifyFile() {
    try {
      const blocks = this.recoverBlocks();
      return {
        valid: true,
        blockCount: blocks.length,
        headHash: blocks[blocks.length - 1].hash,
        genesisHash: blocks[0].hash,
        verifiedAt: new Date().toISOString()
      };
    } catch (err) {
      return {
        valid: false,
        error: err.message,
        brokenIndex: err.brokenIndex !== undefined ? err.brokenIndex : -1,
        code: err.code || 'ERR_VERIFICATION_FAILED'
      };
    }
  }

  /**
   * Attaches this persistence instance to an active AuditLedger.
   * @param {AuditLedger} ledger
   * @returns {AuditFilePersistence}
   */
  attach(ledger) {
    this.ledger = ledger;
    ledger.persistence = this;
    return this;
  }

  /**
   * Flushes and cleans up any open buffers.
   */
  close() {
    this.flush();
  }
}

module.exports = {
  AuditFilePersistence,
  FilePersistence: AuditFilePersistence,
  LedgerPersistenceError
};
