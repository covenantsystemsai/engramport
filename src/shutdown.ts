/**
 * Stopping cleanly when the platform asks (ECS sends SIGTERM, then stops the
 * task 30 seconds later). Stop taking new connections, let requests in flight
 * finish, close the database pool, then exit. If that takes longer than the
 * grace period, exit anyway, so the platform never has to kill the process
 * mid-write: each decision is one database transaction, so a cut request is
 * never half-applied.
 */

export interface Closable {
  close(callback: (err?: Error) => void): unknown;
  /** Node's HTTP server: drop connections that are only being kept alive. */
  closeIdleConnections?(): void;
}

export interface ShutdownOptions {
  /** How long requests in flight get to finish. Default 25 s, under ECS's 30. */
  graceMs?: number;
  /** What else to close after the listener, such as the database pool. */
  closers?: Array<() => Promise<unknown>>;
  /** For tests. */
  exit?: (code: number) => void;
  log?: (line: string) => void;
}

/** Stop `server` once; returns the exit code it used. */
export async function shutdown(server: Closable, opts: ShutdownOptions = {}): Promise<number> {
  const log = opts.log ?? ((line: string) => console.error(line));
  const exit = opts.exit ?? ((code: number) => process.exit(code));
  const graceMs = opts.graceMs ?? 25_000;
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<"late">((resolve) => {
    timer = setTimeout(() => resolve("late"), graceMs);
    timer.unref?.();
  });
  const drain = (async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeIdleConnections?.();
    });
    for (const close of opts.closers ?? []) {
      try {
        await close();
      } catch (err) {
        log(`[engramport] shutdown: ${(err as Error).message}`);
      }
    }
    return "done" as const;
  })();
  const outcome = await Promise.race([drain, deadline]);
  if (timer) clearTimeout(timer);
  const code = outcome === "done" ? 0 : 1;
  log(outcome === "done" ? "[engramport] stopped cleanly" : "[engramport] stopped with requests still running");
  exit(code);
  return code;
}

/** Call `shutdown` on the first SIGTERM or SIGINT; ignore repeats. */
export function stopOnSignals(server: Closable, opts: ShutdownOptions = {}): void {
  let stopping = false;
  const onSignal = (signal: string) => {
    if (stopping) return;
    stopping = true;
    (opts.log ?? ((line: string) => console.error(line)))(`[engramport] ${signal}: stopping`);
    void shutdown(server, opts);
  };
  process.once("SIGTERM", () => onSignal("SIGTERM"));
  process.once("SIGINT", () => onSignal("SIGINT"));
}
