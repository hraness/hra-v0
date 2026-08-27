import { describe, expect, test } from "bun:test";

import {
  agentTasksDeferredTask,
  agentTasksReviewTask,
  createAgentTasksDirectWorld,
  parseAgentTasksDirectWorld,
} from "./world";

describe("Agent Tasks Direct world", () => {
  test("accepts, clones, and JSON-round-trips the canonical world", () => {
    const source = createAgentTasksDirectWorld();
    const parsed = parseAgentTasksDirectWorld(source);
    const roundTripped = parseAgentTasksDirectWorld(JSON.parse(JSON.stringify(source)) as unknown);

    expect(parsed).toEqual(source);
    expect(roundTripped).toEqual(source);
    expect(parsed).not.toBe(source);
    expect(parsed.views).not.toBe(source.views);
    expect(parsed.details).not.toBe(source.details);
  });

  test("rejects unknown keys and prototype-pollution keys at nested boundaries", () => {
    const world = createAgentTasksDirectWorld();
    expect(() => parseAgentTasksDirectWorld({ ...world, surprise: true })).toThrow();
    expect(() => parseAgentTasksDirectWorld({
      ...world,
      scripts: { ...world.scripts, surprise: true },
    })).toThrow();
    expect(() => parseAgentTasksDirectWorld({
      ...world,
      scripts: { ...world.scripts, ["__proto__"]: {} },
    })).toThrow("cannot contain the __proto__ key");
  });

  test("rejects selections without an active queue row and detail", () => {
    const missingRow = createAgentTasksDirectWorld();
    missingRow.views.all = { cursor: null, kind: "ready", tasks: [] };
    expect(() => parseAgentTasksDirectWorld(missingRow)).toThrow(
      "selected task must exist in the active ready view",
    );

    const missingDetail = createAgentTasksDirectWorld();
    missingDetail.details = missingDetail.details.filter(({ task }) => task.key !== agentTasksReviewTask.key);
    expect(() => parseAgentTasksDirectWorld(missingDetail)).toThrow(
      "selected task must have a detail fixture",
    );
  });

  test("rejects a rendered queue row without a deterministic detail", () => {
    const world = createAgentTasksDirectWorld();
    world.details = world.details.filter(({ task }) => task.key !== agentTasksDeferredTask.key);
    expect(() => parseAgentTasksDirectWorld(world)).toThrow(
      `all view task ${agentTasksDeferredTask.key} must have a detail fixture`,
    );
  });

  test("rejects pagination controls and rows without exact deterministic backing", () => {
    const missingStep = createAgentTasksDirectWorld();
    if (missingStep.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    missingStep.views.all.cursor = "page:all:missing";
    expect(() => parseAgentTasksDirectWorld(missingStep)).toThrow(
      "all view cursor page:all:missing must resolve to null through the exact page script",
    );

    const missingDetail = createAgentTasksDirectWorld();
    if (missingDetail.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    missingDetail.views.all.cursor = "page:all:1";
    missingDetail.scripts.pages = [{
      cursor: "page:all:1",
      nextCursor: null,
      tasks: [{ ...agentTasksReviewTask, key: "AT-00ZZ0ZZ" }],
      view: "all",
    }];
    expect(() => parseAgentTasksDirectWorld(missingDetail)).toThrow(
      "Page all:page:all:1 task AT-00ZZ0ZZ must have a detail fixture",
    );

    const duplicateRow = createAgentTasksDirectWorld();
    if (duplicateRow.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    duplicateRow.views.all.cursor = "page:all:1";
    duplicateRow.scripts.pages = [{
      cursor: "page:all:1",
      nextCursor: null,
      tasks: [agentTasksReviewTask, structuredClone(agentTasksReviewTask)],
      view: "all",
    }];
    expect(() => parseAgentTasksDirectWorld(duplicateRow)).toThrow(
      "Page all:page:all:1 task keys must be unique",
    );

    const duplicateStep = createAgentTasksDirectWorld();
    if (duplicateStep.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    duplicateStep.views.all.cursor = "page:all:1";
    const page = {
      cursor: "page:all:1",
      nextCursor: null,
      tasks: [],
      view: "all" as const,
    };
    duplicateStep.scripts.pages = [page, structuredClone(page)];
    expect(() => parseAgentTasksDirectWorld(duplicateStep)).toThrow(
      "Page script identities must be unique",
    );

    const missingNextStep = createAgentTasksDirectWorld();
    if (missingNextStep.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    missingNextStep.views.all.cursor = "page:all:1";
    missingNextStep.scripts.pages = [{
      cursor: "page:all:1",
      nextCursor: "page:all:2",
      tasks: [],
      view: "all",
    }];
    expect(() => parseAgentTasksDirectWorld(missingNextStep)).toThrow(
      "all view cursor page:all:2 must resolve to null through the exact page script",
    );

    const validChain = createAgentTasksDirectWorld();
    if (validChain.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    validChain.views.all.cursor = "page:all:1";
    validChain.scripts.pages = [{
      cursor: "page:all:1",
      nextCursor: "page:all:2",
      tasks: [],
      view: "all",
    }, {
      cursor: "page:all:2",
      nextCursor: null,
      tasks: [],
      view: "all",
    }];
    expect(() => parseAgentTasksDirectWorld(validChain)).not.toThrow();

    const orphanStep = createAgentTasksDirectWorld();
    if (orphanStep.views.all.kind !== "ready") throw new Error("The all view must be ready.");
    orphanStep.views.all.cursor = "page:all:1";
    orphanStep.scripts.pages = [{
      cursor: "page:ready:orphan",
      nextCursor: null,
      tasks: [],
      view: "ready",
    }, {
      cursor: "page:all:1",
      nextCursor: null,
      tasks: [],
      view: "all",
    }];
    expect(() => parseAgentTasksDirectWorld(orphanStep)).toThrow(
      "Page ready:page:ready:orphan must match the current ready cursor null",
    );
  });

  test("rejects duplicate identities and command/response transition drift", () => {
    const duplicate = createAgentTasksDirectWorld();
    duplicate.views.all = {
      cursor: null,
      kind: "ready",
      tasks: [agentTasksReviewTask, structuredClone(agentTasksReviewTask)],
    };
    expect(() => parseAgentTasksDirectWorld(duplicate)).toThrow("all view task keys must be unique");

    const mismatch = createAgentTasksDirectWorld();
    mismatch.scripts.commands = [{
      request: {
        kind: "acceptSubmission",
        reviewRevision: 4,
        submissionId: "sub_01J3ABCDEFGHJKMNPQRSTVWXYZ",
        taskKey: agentTasksReviewTask.key,
      },
      outcome: {
        kind: "response",
        value: { requestId: "req_wrong", transition: "rejected" },
      },
    }];
    expect(() => parseAgentTasksDirectWorld(mismatch)).toThrow(
      "acceptSubmission cannot produce rejected",
    );
  });

  test("rejects duplicate, cross-task, and out-of-order run evidence", () => {
    const duplicate = createAgentTasksDirectWorld();
    const detail = duplicate.details[0];
    const run = detail?.runs?.[0];
    if (detail === undefined || run === undefined) throw new Error("The base world requires one run.");
    detail.runs = [run, structuredClone(run)];
    expect(() => parseAgentTasksDirectWorld(duplicate)).toThrow("Run IDs");

    const crossTask = createAgentTasksDirectWorld();
    const crossTaskRun = crossTask.details[0]?.runs?.[0];
    if (crossTaskRun === undefined) throw new Error("The base world requires one run.");
    crossTaskRun.taskKey = "AT-45EF6GH";
    expect(() => parseAgentTasksDirectWorld(crossTask)).toThrow("must belong");

    const outOfOrder = createAgentTasksDirectWorld();
    const events = outOfOrder.details[0]?.runs?.[0]?.events;
    if (events === undefined || events[1] === undefined) throw new Error("The base world requires two events.");
    events[1].sequence = events[0]?.sequence ?? 1;
    expect(() => parseAgentTasksDirectWorld(outOfOrder)).toThrow(
      "run view events violate sequence or display transcript laws",
    );
  });
});
