/** LexWatt wire error (spec §4.3): code + retryable, nothing else. */
export class LexwattError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, retryable = false) {
    super(code);
    this.code = code;
    this.retryable = retryable;
  }
}

export function errCode(e: unknown): string {
  return e instanceof LexwattError ? e.code : "INTERNAL";
}
