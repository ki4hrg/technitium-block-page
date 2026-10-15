import type { Child } from "hono/jsx";
import { raw } from "hono/html";

const CSS = `
:root {
  --bg: #f6f7f9; --surface: #ffffff; --border: #e3e6eb; --text: #1b1f24; --muted: #5d6673;
  --accent: #2f5bd3; --accent-text: #ffffff; --danger: #b42318; --ok: #1a7f37; --warn: #9a6700;
  --chip: #eef1f6; --radius: 12px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --surface: #171b21; --border: #2a3039; --text: #e7eaee; --muted: #9aa4b2;
    --accent: #6d93ff; --accent-text: #0b0e12; --danger: #ff7b72; --ok: #56d364; --warn: #e3b341;
    --chip: #222831;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 760px; margin: 0 auto; padding: 24px 16px 64px; }
header.top { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; }
header.top a { color: inherit; text-decoration: none; font-weight: 600; }
h1 { font-size: 1.6rem; margin: 0 0 4px; line-height: 1.25; overflow-wrap: anywhere; }
h2 { font-size: 1.05rem; margin: 0 0 12px; }
.muted { color: var(--muted); }
.small { font-size: .875rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 18px; margin: 16px 0; }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.between { justify-content: space-between; }
.stack > * + * { margin-top: 10px; }
button, .btn { appearance: none; border: 1px solid var(--border); background: var(--chip); color: var(--text);
  border-radius: 999px; padding: 8px 14px; font: inherit; font-size: .925rem; cursor: pointer; text-decoration: none;
  display: inline-block; }
button.primary, .btn.primary { background: var(--accent); color: var(--accent-text); border-color: transparent; }
button.danger { color: var(--danger); }
button:disabled { opacity: .5; cursor: default; }
input[type=text], select, textarea { font: inherit; color: var(--text); background: var(--bg);
  border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; }
textarea { width: 100%; min-height: 64px; }
form { margin: 0; }
.code { font: 600 2.2rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .08em; }
.qr { width: 168px; height: 168px; background: #fff; padding: 8px; border-radius: 8px; flex: none; }
.qr svg { width: 100%; height: 100%; display: block; }
.chip { display: inline-block; background: var(--chip); border-radius: 999px; padding: 2px 10px; font-size: .8rem; }
.chip.ok { color: var(--ok); } .chip.warn { color: var(--warn); } .chip.danger { color: var(--danger); }
.list { list-style: none; margin: 0; padding: 0; }
.list > li { padding: 10px 0; border-top: 1px solid var(--border); }
.list > li:first-child { border-top: 0; padding-top: 0; }
.domain { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; overflow-wrap: anywhere; }
.status { font-weight: 600; }
.status.ok { color: var(--ok); } .status.warn { color: var(--warn); } .status.danger { color: var(--danger); }
.notice { border-left: 3px solid var(--warn); padding: 8px 12px; background: var(--chip); border-radius: 6px; }
.error { border-left-color: var(--danger); }
label.check { display: flex; gap: 8px; align-items: center; }
@media (max-width: 520px) { .code { font-size: 1.8rem; } .qr { width: 140px; height: 140px; } }
`;

export function Layout(props: { title: string; children: Child; nav?: Child; script?: string }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="robots" content="noindex" />
        <title>{props.title}</title>
        <style>{raw(CSS)}</style>
      </head>
      <body>
        <main>
          {props.nav}
          {props.children}
        </main>
        {props.script ? <script>{raw(props.script)}</script> : null}
      </body>
    </html>
  );
}

export function fmtTime(ms: number): string {
  return new Date(ms).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
}

export function fmtAgo(ms: number, now = Date.now()): string {
  const s = Math.round((now - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return fmtTime(ms);
}
