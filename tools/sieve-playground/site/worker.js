/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: the engine is the server's sieve-rs built for wasm32-wasip1 (see
// build.sh), so this worker gives it the few WASI calls it makes. The clock
// is the point: currentdate, and the Date headers of the replies a script
// writes, read the playground's current time from it.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let memory;
let engine;
let panicMessage = null;
// Seconds since the epoch the clock reports, or null for the real clock.
let clockSeconds = null;

const view = () => new DataView(memory.buffer);
const bytes = (ptr, len) => new Uint8Array(memory.buffer, ptr, len);

const SUCCESS = 0;
const CLOCK_MONOTONIC = 1;

const wasi = {
  clock_time_get(clockId, _precision, timePtr) {
    const ms =
      clockId === CLOCK_MONOTONIC ? performance.now() : clockSeconds !== null ? clockSeconds * 1000 : Date.now();
    view().setBigUint64(timePtr, BigInt(Math.round(ms)) * 1000000n, true);
    return SUCCESS;
  },
  random_get(ptr, len) {
    for (let offset = 0; offset < len; offset += 65536) {
      crypto.getRandomValues(bytes(ptr + offset, Math.min(65536, len - offset)));
    }
    return SUCCESS;
  },
  environ_sizes_get(countPtr, sizePtr) {
    view().setUint32(countPtr, 0, true);
    view().setUint32(sizePtr, 0, true);
    return SUCCESS;
  },
  environ_get() {
    return SUCCESS;
  },
  fd_write(_fd, iovs, iovsLen, writtenPtr) {
    const v = view();
    let written = 0;
    let text = "";
    for (let i = 0; i < iovsLen; i++) {
      const ptr = v.getUint32(iovs + i * 8, true);
      const len = v.getUint32(iovs + i * 8 + 4, true);
      text += decoder.decode(bytes(ptr, len));
      written += len;
    }
    v.setUint32(writtenPtr, written, true);
    if (text.trim()) console.warn(text.trim());
    return SUCCESS;
  },
  proc_exit(code) {
    throw new WebAssembly.RuntimeError(`The engine exited with code ${code}`);
  },
};

const playground = {
  panicked(ptr, len) {
    panicMessage = decoder.decode(bytes(ptr, len).slice());
  },
};

async function load() {
  const url = new URL("./sieve_playground.wasm", import.meta.url);
  const imports = { wasi_snapshot_preview1: wasi, playground };
  let instance;
  try {
    ({ instance } = await WebAssembly.instantiateStreaming(fetch(url), imports));
  } catch {
    // Served without application/wasm: compile from the bytes instead.
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status} loading the engine`);
    ({ instance } = await WebAssembly.instantiate(await response.arrayBuffer(), imports));
  }
  engine = instance.exports;
  memory = engine.memory;
  engine.playground_init();
}

function put(data) {
  const ptr = engine.playground_alloc(data.length);
  bytes(ptr, data.length).set(data);
  return [ptr, data.length];
}

function call(op, payload) {
  const [opPtr, opLen] = put(encoder.encode(op));
  const [payloadPtr, payloadLen] = put(encoder.encode(payload === undefined ? "null" : JSON.stringify(payload)));
  const packed = BigInt.asUintN(64, engine.playground_call(opPtr, opLen, payloadPtr, payloadLen));
  const ptr = Number(packed >> 32n);
  const len = Number(packed & 0xffffffffn);
  const text = decoder.decode(bytes(ptr, len).slice());
  engine.playground_free(ptr, len);
  const reply = JSON.parse(text);
  if ("error" in reply) throw new Error(reply.error);
  return reply.ok;
}

const ops = {
  version: () => call("version"),
  capabilities: () => call("capabilities"),
  defaults: () => call("defaults"),
  compile: (request) => call("compile", request),
  run: (request) => {
    const currentTime = request?.settings?.currentTime;
    clockSeconds = Number.isFinite(currentTime) ? currentTime : null;
    try {
      return call("run", request);
    } finally {
      clockSeconds = null;
    }
  },
};

const ready = load().then(
  () => {
    self.postMessage({ type: "ready" });
    return true;
  },
  (err) => {
    self.postMessage({ type: "init-error", error: String(err && err.message ? err.message : err) });
    return false;
  },
);

self.onmessage = async (event) => {
  const { id, op, payload } = event.data;
  if (!(await ready)) return;
  try {
    const fn = ops[op];
    if (!fn) throw new Error(`Unknown operation ${op}`);
    const result = fn(payload);
    self.postMessage({ id, result });
  } catch (err) {
    const fatal = err instanceof WebAssembly.RuntimeError;
    const message = fatal && panicMessage ? panicMessage : String(err && err.message ? err.message : err);
    self.postMessage({ id, error: message, fatal });
  }
};
