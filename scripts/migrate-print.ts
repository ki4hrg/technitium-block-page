// Prints a suggested Advanced Blocking app config built from Technitium's current built-in
// blocking settings plus the VLANs in policy.yaml. Nothing is written to Technitium.
//
//   TECHNITIUM_TOKEN=... POLICY_FILE=config/policy.yaml npm run migrate:print > advanced-blocking.json

import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { parsePolicy } from "../src/config.js";
import { TechnitiumClient } from "../src/technitium/client.js";
import type { AdvancedBlockingConfig } from "../src/technitium/advancedBlocking.js";

const token = process.env.TECHNITIUM_TOKEN;
if (!token) throw new Error("Set TECHNITIUM_TOKEN");
const policy = parsePolicy(parseYaml(readFileSync(process.env.POLICY_FILE ?? "config/policy.yaml", "utf8")));
const client = new TechnitiumClient(policy.technitium.url, token);

const settings = await client.getSettings();
const allowedRes = await fetch(new URL("/api/allowed/export", policy.technitium.url), {
  headers: { Authorization: `Bearer ${token}` },
});
const allowed = allowedRes.ok
  ? (await allowedRes.text())
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
  : [];

const existing = await client.getAppConfig(policy.technitium.advancedBlockingAppName).catch(() => null);
if (existing) {
  console.error(
    `Note: "${policy.technitium.advancedBlockingAppName}" already has a config. Merge by hand rather than replacing it.`,
  );
}

const networkGroupMap: Record<string, string> = {};
for (const v of policy.vlans) for (const cidr of v.cidrs) networkGroupMap[cidr] = v.group;

const groups = [...new Set(policy.vlans.map((v) => v.group))].map((name) => ({
  name,
  enableBlocking: true,
  allowTxtBlockingReport: true,
  blockAsNxDomain: false,
  blockingAddresses: [policy.blockPage.ip],
  allowed,
  blocked: [],
  allowListUrls: [],
  blockListUrls: settings.blockListUrls ?? [],
  allowedRegex: [],
  blockedRegex: [],
  regexAllowListUrls: [],
  regexBlockListUrls: [],
  adblockListUrls: [],
}));

const config: AdvancedBlockingConfig = {
  enableBlocking: true,
  blockingAnswerTtl: 10,
  blockListUrlUpdateIntervalHours: 24,
  localEndPointGroupMap: {},
  networkGroupMap,
  groups,
};

console.log(JSON.stringify(config, null, 2));
console.error(
  [
    "",
    "Next steps:",
    "  1. Tailor each group's blockListUrls (e.g. stricter lists for kids).",
    "  2. Paste this into Apps > Advanced Blocking > Config in Technitium.",
    "  3. Clear Settings > Blocking > block list URLs (built-in lists run independently of the app).",
    "     Keep Settings > Blocking enabled, or rely on the app only.",
  ].join("\n"),
);
