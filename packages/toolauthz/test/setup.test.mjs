import { execSync } from "child_process";
import { existsSync, readFileSync, mkdirSync, writeFileSync, rmSync, readdirSync } from "fs";
import { join, resolve } from "path";
import { tmpdir, homedir } from "os";
import { strict as assert } from "assert";

const SETUP_SCRIPT = resolve(import.meta.dirname, "..", "bin", "setup.mjs");
const AGENTS_SKILLS = resolve(homedir(), ".agents", "skills");

// Helpers
function freshDir(name) {
  const dir = join(tmpdir(), `tap-test-${name}-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function run(cwd) {
  return execSync(`node ${SETUP_SCRIPT}`, { cwd, encoding: "utf8" });
}

function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
}

function cleanGlobalSkills() {
  for (const name of ["setup-tap", "setup-tap-skill", "setup-google", "setup-telegram"]) {
    rmSync(join(AGENTS_SKILLS, name), { recursive: true, force: true });
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
    failed++;
  }
}

console.log("setup.mjs tests\n");

// ── Claude Code ──────────────────────────────────────────────────────────────

console.log("Claude Code (fresh project):");

const ccDir = freshDir("claude-code");
cleanGlobalSkills();
try {
  const output = run(ccDir);

  test("installs 4 commands to .claude/commands/", () => {
    for (const f of ["setup-tap.md", "setup-tap-skill.md", "setup-google.md", "setup-telegram.md"]) {
      assert.ok(existsSync(join(ccDir, ".claude", "commands", f)), `missing ${f}`);
    }
  });

  test("commands have frontmatter with description", () => {
    const content = readFileSync(join(ccDir, ".claude", "commands", "setup-tap.md"), "utf8");
    assert.ok(content.startsWith("---"), "missing frontmatter start");
    assert.ok(content.includes("description:"), "missing description field");
  });

  test("commands keep $ARGUMENTS for Claude Code", () => {
    const content = readFileSync(join(ccDir, ".claude", "commands", "setup-tap.md"), "utf8");
    assert.ok(content.includes("$ARGUMENTS"), "$ARGUMENTS should be present");
  });

  test("installs global skills to ~/.agents/skills/", () => {
    for (const name of ["setup-tap", "setup-tap-skill", "setup-google", "setup-telegram"]) {
      assert.ok(
        existsSync(join(AGENTS_SKILLS, name, "SKILL.md")),
        `missing ~/.agents/skills/${name}/SKILL.md`
      );
    }
  });

  test("global SKILL.md strips $ARGUMENTS", () => {
    const content = readFileSync(join(AGENTS_SKILLS, "setup-tap", "SKILL.md"), "utf8");
    assert.ok(!content.includes("$ARGUMENTS"), "$ARGUMENTS should be stripped");
  });

  test("does NOT create project skills/ dir (no SOUL.md)", () => {
    assert.ok(!existsSync(join(ccDir, "skills")), "skills/ dir should not exist");
  });

  test("output mentions Claude Code", () => {
    assert.ok(output.includes("Claude Code"), "should mention Claude Code");
  });

  test("output mentions /setup-tap", () => {
    assert.ok(output.includes("/setup-tap"), "should tell user about /setup-tap");
  });

  test("output mentions /setup-tap-skill", () => {
    assert.ok(output.includes("/setup-tap-skill"), "should tell user about /setup-tap-skill");
  });
} finally {
  cleanup(ccDir);
}

// ── OpenClaw ─────────────────────────────────────────────────────────────────

console.log("\nOpenClaw (project with SOUL.md):");

const ocDir = freshDir("openclaw");
cleanGlobalSkills();
writeFileSync(join(ocDir, "SOUL.md"), "# My Agent\n");
try {
  const output = run(ocDir);

  test("installs project skills/ when SOUL.md exists", () => {
    for (const name of ["setup-tap", "setup-tap-skill", "setup-google", "setup-telegram"]) {
      assert.ok(
        existsSync(join(ocDir, "skills", name, "SKILL.md")),
        `missing skills/${name}/SKILL.md`
      );
    }
  });

  test("project SKILL.md has valid frontmatter", () => {
    const content = readFileSync(join(ocDir, "skills", "setup-tap", "SKILL.md"), "utf8");
    assert.ok(content.startsWith("---"), "missing frontmatter start");
    assert.ok(content.includes("description:"), "missing description");
  });

  test("project SKILL.md strips $ARGUMENTS", () => {
    const content = readFileSync(join(ocDir, "skills", "setup-tap", "SKILL.md"), "utf8");
    assert.ok(!content.includes("$ARGUMENTS"), "$ARGUMENTS should be stripped");
  });

  test("output mentions OpenClaw project skills", () => {
    assert.ok(output.includes("OpenClaw project skills"), "should mention OpenClaw");
  });

  test("also installs .claude/commands/ alongside", () => {
    assert.ok(
      existsSync(join(ocDir, ".claude", "commands", "setup-tap.md")),
      "should still install Claude Code commands"
    );
  });
} finally {
  cleanup(ocDir);
}

// ── Hermes ───────────────────────────────────────────────────────────────────

console.log("\nHermes (no SOUL.md, uses global skills):");

const hmDir = freshDir("hermes");
cleanGlobalSkills();
try {
  run(hmDir);

  test("installs global skills to ~/.agents/skills/", () => {
    for (const name of ["setup-tap", "setup-tap-skill", "setup-google", "setup-telegram"]) {
      assert.ok(
        existsSync(join(AGENTS_SKILLS, name, "SKILL.md")),
        `missing ~/.agents/skills/${name}/SKILL.md`
      );
    }
  });

  test("does NOT create project skills/ dir", () => {
    assert.ok(!existsSync(join(hmDir, "skills")), "skills/ dir should not exist");
  });
} finally {
  cleanup(hmDir);
}

// ── Idempotency ──────────────────────────────────────────────────────────────

console.log("\nIdempotency:");

const idDir = freshDir("idempotent");
cleanGlobalSkills();
try {
  run(idDir);
  run(idDir); // run twice

  test("running twice does not duplicate files", () => {
    const files = readdirSync(join(idDir, ".claude", "commands"));
    assert.equal(files.length, 4, `expected 4 files, got ${files.length}`);
  });

  test("content is identical after second run", () => {
    const content = readFileSync(join(idDir, ".claude", "commands", "setup-tap.md"), "utf8");
    assert.ok(content.includes("TAP Credential Proxy"), "content should be intact");
  });
} finally {
  cleanup(idDir);
}

// ── Skill Content Quality ────────────────────────────────────────────────────

console.log("\nSkill content quality:");

const sqDir = freshDir("quality");
cleanGlobalSkills();
try {
  run(sqDir);
  const tap = readFileSync(join(sqDir, ".claude", "commands", "setup-tap.md"), "utf8");

  test("setup-tap detects SOUL.md vs CLAUDE.md", () => {
    assert.ok(tap.includes("SOUL.md"), "should mention SOUL.md detection");
    assert.ok(tap.includes("CLAUDE.md"), "should mention CLAUDE.md");
  });

  test("setup-tap includes X-TAP-Method in curl template", () => {
    assert.ok(tap.includes("X-TAP-Method"), "should include X-TAP-Method header");
  });

  test("setup-tap includes anti-bypass language", () => {
    assert.ok(
      tap.includes("Do not search for alternative"),
      "should tell agent not to bypass proxy"
    );
  });

  test("setup-tap description enables discovery for 'credential' queries", () => {
    const desc = tap.match(/^description:\s*(.+)$/m)?.[1] || "";
    assert.ok(desc.includes("credential"), "description should mention credentials");
    assert.ok(desc.includes("API"), "description should mention API");
  });

  test("setup-tap has exact curl template (no searching needed)", () => {
    assert.ok(tap.includes('curl -X POST "$TAP_PROXY_URL/forward"'), "should have exact curl");
    assert.ok(tap.includes("X-TAP-Key"), "should have X-TAP-Key header");
    assert.ok(tap.includes("X-TAP-Credential"), "should have X-TAP-Credential header");
    assert.ok(tap.includes("X-TAP-Target"), "should have X-TAP-Target header");
  });

  test("setup-tap tests connectivity (health check)", () => {
    assert.ok(tap.includes("/health"), "should test health endpoint");
  });

  test("setup-tap lists available services after setup", () => {
    assert.ok(tap.includes("/agent/services"), "should list services");
  });

  test("setup-tap can roll into service-specific skill setup", () => {
    assert.ok(tap.includes("service-specific TAP skill setup"), "should offer connector-specific follow-up");
    assert.ok(tap.includes("for all credentials or just selected ones"), "should support all vs selected credential choice");
    assert.ok(tap.includes("same workflow as `/setup-tap-skill`"), "should reuse the skill-validation workflow");
  });

  test("setup-tap explains Telegram sidecar targets", () => {
    assert.ok(tap.includes("Telethon sidecar"), "should mention Telegram sidecar");
    assert.ok(tap.includes("/me"), "should mention relative Telegram targets");
    assert.ok(tap.includes("https://api.telegram.org"), "should warn against Bot API URL");
  });

  const telegram = readFileSync(join(sqDir, ".claude", "commands", "setup-telegram.md"), "utf8");
  const tapSkill = readFileSync(join(sqDir, ".claude", "commands", "setup-tap-skill.md"), "utf8");

  test("setup-telegram warns against Bot API usage", () => {
    assert.ok(telegram.includes("/me"), "should mention Telethon bridge endpoints");
    assert.ok(telegram.includes("getMe"), "should mention wrong Bot API method names");
    assert.ok(telegram.includes("https://api.telegram.org"), "should warn against Bot API URL");
  });

  test("setup-tap-skill requires real validation", () => {
    assert.ok(tapSkill.includes("/agent/services"), "should inspect available services");
    assert.ok(tapSkill.includes("at least one real request succeeded"), "should require real validation");
    assert.ok(tapSkill.includes("Do not stop at a generic template"), "should reject unvalidated templates");
    assert.ok(tapSkill.includes("1 to 3 focused questions"), "should allow a short interactive intake");
    assert.ok(tapSkill.includes("read, write, or both"), "should ask what the user wants to validate");
  });
} finally {
  cleanup(sqDir);
}

// ── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests, ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
