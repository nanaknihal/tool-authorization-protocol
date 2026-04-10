#!/usr/bin/env node

import { cpSync, mkdirSync, existsSync, readdirSync, readFileSync, writeFileSync } from "fs";
import { resolve, dirname, join, basename } from "path";
import { fileURLToPath } from "url";
import { homedir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const commandsSource = resolve(__dirname, "..", "commands");
const cwd = process.cwd();

const files = readdirSync(commandsSource).filter((f) => f.endsWith(".md"));

if (files.length === 0) {
  console.error("Error: no command files found in package.");
  process.exit(1);
}

// 1. Claude Code / NanoClaw / Cursor / Gemini CLI — .claude/commands/*.md
const claudeTarget = resolve(cwd, ".claude", "commands");
mkdirSync(claudeTarget, { recursive: true });
for (const f of files) {
  cpSync(join(commandsSource, f), join(claudeTarget, f));
}
console.log(`  ✓ .claude/commands/ (Claude Code, NanoClaw, Cursor, Gemini CLI)`);

// Strip $ARGUMENTS (Claude Code-specific) for AgentSkills format
function copyAsSkill(src, destDir) {
  mkdirSync(destDir, { recursive: true });
  let content = readFileSync(src, "utf8");
  content = content.replace(/^\$ARGUMENTS\s*$/m, "").trimEnd() + "\n";
  writeFileSync(join(destDir, "SKILL.md"), content);
}

// 2. OpenClaw / Hermes — ~/.agents/skills/*/SKILL.md (shared convention)
const agentsTarget = resolve(homedir(), ".agents", "skills");
for (const f of files) {
  copyAsSkill(join(commandsSource, f), join(agentsTarget, basename(f, ".md")));
}
console.log(`  ✓ ~/.agents/skills/  (OpenClaw, Hermes)`);

// 3. If SOUL.md exists (OpenClaw project), also install to project skills/ dir
if (existsSync(resolve(cwd, "SOUL.md")) || existsSync(resolve(cwd, "soul.md"))) {
  const projSkills = resolve(cwd, "skills");
  for (const f of files) {
    copyAsSkill(join(commandsSource, f), join(projSkills, basename(f, ".md")));
  }
  console.log(`  ✓ skills/            (OpenClaw project skills)`);
}

console.log(
  `\nDone! Tell your agent: /setup-tap\n` +
    `Then use /setup-tap-skill for each important connector to turn it into a tested service-specific skill.\n`
);
