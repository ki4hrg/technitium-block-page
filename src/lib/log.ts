export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

function emit(level: string, msg: string, fields?: Record<string, unknown>) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields });
  (level === "error" ? console.error : console.log)(line);
}

export const log: Logger = {
  info: (m, f) => emit("info", m, f),
  warn: (m, f) => emit("warn", m, f),
  error: (m, f) => emit("error", m, f),
};

export const silentLog: Logger = { info() {}, warn() {}, error() {} };
