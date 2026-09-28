"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const actionLog = require("./log.cts");

test("sanitizes C1 controls and Unicode line separators", () => {
  assert.equal(
    actionLog.sanitizeLogText("before\u0080next\u0085line\u009b31m\u009fafter\u2028tail\u2029end"),
    "before_next_line_31m_after_tail_end",
  );
  assert.equal(
    actionLog.workflowEscape("first\u0085second\u2028third\u2029fourth%"),
    "first_second_third_fourth%25",
  );
});

test("keeps workflow command escaping inside the debug-line byte bound", () => {
  const escaped = actionLog.workflowEscape("%".repeat(4096));
  assert.ok(Buffer.byteLength(escaped, "utf8") <= 4096);
  assert.ok(escaped.endsWith("...[truncated]"));
});
