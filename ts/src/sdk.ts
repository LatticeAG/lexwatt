/** LexWatt local SDK client (spec §9.1): newline-free 4-byte-BE-length
 * framed JSON over a Unix domain socket.  Requests carry lwq_ IDs; the
 * caller may resend the identical request — same ID + same digest replays
 * the stored response. */

import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { dumps, loads } from "./jcs.ts";
import { LexwattError } from "./errors.ts";

export const FRAME_LIMIT = 1048576;

function requestId(): string {
  return "lwq_" + Buffer.from(randomBytes(16)).toString("base64url").slice(0, 21);
}

export interface Result {
  result: unknown;
}

export interface Failure {
  error: { code: string; retryable: boolean };
}

export class Client {
  private buf = Buffer.alloc(0);
  private pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();
  private sock: Socket | null = null;
  private ready: Promise<void>;
  readonly path: string;

  constructor(path: string) {
    this.path = path;
    this.ready = new Promise((resolve, reject) => {
      const s = connect(this.path);
      s.once("connect", () => resolve());
      s.once("error", (e) => reject(e));
      this.sock = s;
      s.on("data", (d) => this.onData(d));
      s.on("error", () => {
        for (const p of this.pending.values()) p.reject(new LexwattError("INTERNAL"));
        this.pending.clear();
      });
      s.on("close", () => {
        for (const p of this.pending.values()) p.reject(new LexwattError("INTERNAL"));
        this.pending.clear();
      });
    });
  }

  private onData(d: Buffer): void {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      if (this.buf.length < 4) return;
      const n = this.buf.readUInt32BE(0);
      if (n > FRAME_LIMIT) {
        this.sock?.destroy();
        return;
      }
      if (this.buf.length < 4 + n) return;
      const payload = this.buf.subarray(4, 4 + n);
      this.buf = this.buf.subarray(4 + n);
      const msg = loads(payload.toString("utf-8")) as any;
      const id = msg?.id;
      const p = id !== undefined ? this.pending.get(id) : undefined;
      if (p) {
        this.pending.delete(id);
        p.resolve(msg);
      }
    }
  }

  async call(method: string, params: Record<string, unknown>, id?: string): Promise<unknown> {
    await this.ready;
    const reqId = id ?? requestId();
    const frame = Buffer.allocUnsafe(4);
    const body = Buffer.from(dumps({ v: 1, id: reqId, method, params }), "utf-8");
    frame.writeUInt32BE(body.length, 0);
    return new Promise((resolve, reject) => {
      this.pending.set(reqId, { resolve, reject });
      this.sock!.write(Buffer.concat([frame, body]), (e) => {
        if (e) {
          this.pending.delete(reqId);
          reject(e);
        }
      });
    });
  }

  async result(method: string, params: Record<string, unknown>): Promise<unknown> {
    const resp = (await this.call(method, params)) as Result & Failure;
    if (resp.error) {
      throw new LexwattError(resp.error.code, resp.error.retryable);
    }
    return resp.result;
  }

  close(): void {
    this.sock?.destroy();
    this.sock = null;
  }
}
