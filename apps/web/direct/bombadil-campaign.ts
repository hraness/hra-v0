import {
  always,
  eventually,
  extract,
  type ActionGenerator,
  type Formula,
  type JSON as BombadilJson,
} from "@antithesishq/bombadil";
import type {
  ActionTemplate,
  State as BombadilBrowserState,
} from "@antithesishq/bombadil/browser";
import {
  createDirectBombadilActions,
  createDirectBombadilProperties,
} from "@hraness/direct/tooling/bombadil-campaign";

export * from "@antithesishq/bombadil/browser/defaults/properties";

interface TaskWorkspaceObservation {
  readonly [key: string | number | symbol]: BombadilJson;
  readonly controlPlaneNamed: boolean;
  readonly heading: string;
  readonly scenario: string;
  readonly workspacePresent: boolean;
}

const taskWorkspace = extract<BombadilBrowserState, TaskWorkspaceObservation>((state) => {
  const frame = state.document.querySelector("[data-agent-tasks-direct]");
  const workspace = frame?.querySelector("section.task-workspace");
  return {
    controlPlaneNamed:
      workspace?.getAttribute("aria-label")?.endsWith(" task control plane") === true,
    heading: workspace?.querySelector("h2")?.textContent?.trim() ?? "",
    scenario: frame?.getAttribute("data-agent-tasks-direct") ?? "",
    workspacePresent: workspace !== null && workspace !== undefined,
  };
});
const properties = createDirectBombadilProperties();

export const direct_safe_actions: ActionGenerator<ActionTemplate> =
  createDirectBombadilActions();
export const direct_exact_contract: Formula = properties.exactContract;
export const direct_stable_catalog: Formula = properties.stableCatalog;
export const direct_no_declared_violations: Formula = properties.noDeclaredViolations;
export const direct_eventual_quiescence: Formula = properties.eventualQuiescence;
export const hra_task_workspace_persists: Formula = always(
  eventually(() =>
    taskWorkspace.current.scenario === "tasks-rich-review"
    && taskWorkspace.current.workspacePresent
    && taskWorkspace.current.controlPlaneNamed
    && taskWorkspace.current.heading === "Tasks"
  ).within(10, "seconds"),
);
