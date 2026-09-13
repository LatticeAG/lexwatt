/** RFC 8785 (JCS) canonical JSON under the LexWatt integer-only numeric
 * profile (spec §4.1).
 *
 * JS string comparison is already UTF-16 code-unit order, so `sort()`
 * without a comparator is exactly the JCS key ordering.  Numbers are
 * canonical integers with |v| <= 2147483647; booleans are legal JSON.
 */

import { LexwattError } from "./errors.ts";

export const MAX_DEPTH = 32;
export const MAX_JSON_INT = 2147483647;

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function dumps(v: Json): string {
  const parts: string[] = [];
  write(v, parts);
  return parts.join("");
}

export function dumpsBytes(v: Json): Uint8Array {
  return new TextEncoder().encode(dumps(v));
}

function escape(s: string, out: string[]): void {
  out.push('"');
  for (const ch of s) {
    const o = ch.codePointAt(0)!;
    if (ch === '"') out.push('\\"');
    else if (ch === "\\") out.push("\\\\");
    else if (ch === "\b") out.push("\\b");
    else if (ch === "\f") out.push("\\f");
    else if (ch === "\n") out.push("\\n");
    else if (ch === "\r") out.push("\\r");
    else if (ch === "\t") out.push("\\t");
    else if (o < 0x20) out.push("\\u" + o.toString(16).padStart(4, "0"));
    else out.push(ch);
  }
  out.push('"');
}

function write(v: Json, out: string[]): void {
  if (v === null) {
    out.push("null");
  } else if (v === true) {
    out.push("true");
  } else if (v === false) {
    out.push("false");
  } else if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > MAX_JSON_INT) {
      throw new LexwattError("INVALID_INPUT");
    }
    out.push(String(v));
  } else if (typeof v === "string") {
    escape(v, out);
  } else if (Array.isArray(v)) {
    out.push("[");
    v.forEach((item, i) => {
      if (i) out.push(",");
      write(item, out);
    });
    out.push("]");
  } else if (typeof v === "object") {
    out.push("{");
    // JS string < compares UTF-16 code units — exactly JCS ordering
    const keys = Object.keys(v).sort();
    keys.forEach((k, i) => {
      if (i) out.push(",");
      escape(k, out);
      out.push(":");
      write(v[k]!, out);
    });
    out.push("}");
  } else {
    throw new LexwattError("INVALID_INPUT");
  }
}

class Parser {
  pos = 0;
  readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  fail(): never {
    throw new LexwattError("INVALID_INPUT");
  }

  ws(): void {
    while (this.pos < this.s.length && " \t\n\r".includes(this.s[this.pos]!)) this.pos++;
  }

  parse(): Json {
    this.ws();
    const v = this.value(0);
    this.ws();
    if (this.pos !== this.s.length) this.fail();
    return v;
  }

  value(depth: number): Json {
    if (depth > MAX_DEPTH) this.fail();
    const c = this.s[this.pos];
    if (c === undefined) this.fail();
    if (c === "{") return this.obj(depth);
    if (c === "[") return this.arr(depth);
    if (c === '"') return this.string();
    if (c === "t") return this.lit("true", true);
    if (c === "f") return this.lit("false", false);
    if (c === "n") return this.lit("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    this.fail();
  }

  lit(word: string, val: Json): Json {
    if (!this.s.startsWith(word, this.pos)) this.fail();
    this.pos += word.length;
    return val;
  }

  number(): number {
    const start = this.pos;
    if (this.s[this.pos] === "-") this.pos++;
    if (this.s[this.pos] === "0") {
      this.pos++;
      const nx = this.s[this.pos];
      if (nx !== undefined && nx >= "0" && nx <= "9") this.fail();
    } else {
      const c = this.s[this.pos];
      if (c === undefined || c < "1" || c > "9") this.fail();
      while (this.s[this.pos] !== undefined && this.s[this.pos]! >= "0" && this.s[this.pos]! <= "9")
        this.pos++;
    }
    const c = this.s[this.pos];
    if (c === "." || c === "e" || c === "E") this.fail();
    const v = Number(this.s.slice(start, this.pos));
    if (!Number.isInteger(v) || Math.abs(v) > MAX_JSON_INT) this.fail();
    return v;
  }

  string(): string {
    if (this.s[this.pos] !== '"') this.fail();
    this.pos++;
    const out: string[] = [];
    for (;;) {
      if (this.pos >= this.s.length) this.fail();
      const c = this.s[this.pos]!;
      this.pos++;
      if (c === '"') break;
      if (c === "\\") {
        const e = this.s[this.pos];
        this.pos++;
        if (e === '"') out.push('"');
        else if (e === "\\") out.push("\\");
        else if (e === "/") out.push("/");
        else if (e === "b") out.push("\b");
        else if (e === "f") out.push("\f");
        else if (e === "n") out.push("\n");
        else if (e === "r") out.push("\r");
        else if (e === "t") out.push("\t");
        else if (e === "u") out.push(this.uEscape());
        else this.fail();
      } else if (c < " ") {
        this.fail();
      } else {
        out.push(c);
      }
    }
    return out.join("");
  }

  uEscape(): string {
    const hex = this.s.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail();
    this.pos += 4;
    let cp = parseInt(hex, 16);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const esc = this.s.slice(this.pos, this.pos + 2);
      const hex2 = this.s.slice(this.pos + 2, this.pos + 6);
      if (esc !== "\\u" || !/^[0-9a-fA-F]{4}$/.test(hex2)) this.fail();
      const lo = parseInt(hex2, 16);
      if (lo < 0xdc00 || lo > 0xdfff) this.fail();
      this.pos += 6;
      cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      return String.fromCodePoint(cp);
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) this.fail(); // lone low surrogate
    return String.fromCharCode(cp);
  }

  obj(depth: number): Json {
    this.pos++;
    const out: { [k: string]: Json } = {};
    this.ws();
    if (this.s[this.pos] === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      const k = this.string();
      this.ws();
      if (this.s[this.pos] !== ":") this.fail();
      this.pos++;
      this.ws();
      const v = this.value(depth + 1);
      if (k in out) throw new LexwattError("INVALID_INPUT"); // duplicate key
      out[k] = v;
      this.ws();
      const c = this.s[this.pos];
      this.pos++;
      if (c === "}") return out;
      if (c !== ",") this.fail();
    }
  }

  arr(depth: number): Json {
    this.pos++;
    const out: Json[] = [];
    this.ws();
    if (this.s[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.pos];
      this.pos++;
      if (c === "]") return out;
      if (c !== ",") this.fail();
    }
  }
}

export function loads(text: string): Json {
  // reject lone surrogates (unpaired) — TextEncoder would silently fix them
  for (let i = 0; i < text.length; i++) {
    const cu = text.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const lo = text.charCodeAt(i + 1);
      if (lo < 0xdc00 || lo > 0xdfff || Number.isNaN(lo)) throw new LexwattError("INVALID_INPUT");
      i++;
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      throw new LexwattError("INVALID_INPUT");
    }
  }
  if (text.startsWith("﻿")) throw new LexwattError("INVALID_INPUT"); // BOM
  return new Parser(text).parse();
}

export function loadsBytes(data: Uint8Array): Json {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    throw new LexwattError("INVALID_INPUT");
  }
  return loads(text);
}
