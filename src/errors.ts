export class HuntError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "HuntError";
    this.code = code;
  }
}

export function toHuntError(code: string, cause: unknown): HuntError {
  if (cause instanceof HuntError) return cause;
  if (cause && typeof cause === "object") {
    if ("code" in cause && typeof (cause as any).code === "string") {
      const existingCode = (cause as any).code;
      const message = "message" in cause && typeof (cause as any).message === "string" ? (cause as any).message : String(cause);
      return new HuntError(existingCode, message, cause instanceof Error ? { cause } : undefined);
    }
    if ("_tag" in cause && (cause as any)._tag === "FiberFailure" && "cause" in cause) {
      const inner = (cause as any).cause;
      if (inner && typeof inner === "object" && "_tag" in inner && inner._tag === "Fail" && "error" in inner) {
        return toHuntError(code, inner.error);
      }
    }
  }
  const message = cause instanceof Error ? cause.message : String(cause);
  return new HuntError(code, message, cause instanceof Error ? { cause } : undefined);
}
