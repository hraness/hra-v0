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

interface DesktopShellObservation {
  readonly [key: string | number | symbol]: BombadilJson;
  readonly mainNavigationPresent: boolean;
  readonly newPaneControlPresent: boolean;
  readonly productSurfacePresent: boolean;
  readonly scenario: string;
  readonly sessionHeading: string;
}

const desktopShell = extract<BombadilBrowserState, DesktopShellObservation>((state) => {
  const frame = state.document.querySelector("[data-direct-scenario]");
  return {
    mainNavigationPresent:
      frame?.querySelector('nav[aria-label="Main navigation"]') != null,
    newPaneControlPresent: frame?.querySelector(
      'button[aria-label="New pane"], button[aria-label="Choosing a project"]',
    ) != null,
    productSurfacePresent:
      state.document.documentElement.getAttribute("data-hra-surface") === "product"
      && state.document.body.getAttribute("data-hra-surface") === "product",
    scenario: frame?.getAttribute("data-direct-scenario") ?? "",
    sessionHeading: frame?.querySelector("h1")?.textContent?.trim() ?? "",
  };
});
const properties = createDirectBombadilProperties();

export const direct_safe_actions: ActionGenerator<ActionTemplate> =
  createDirectBombadilActions();
export const direct_exact_contract: Formula = properties.exactContract;
export const direct_stable_catalog: Formula = properties.stableCatalog;
export const direct_no_declared_violations: Formula = properties.noDeclaredViolations;
export const direct_eventual_quiescence: Formula = properties.eventualQuiescence;
export const hra_chat_shell_persists: Formula = always(
  eventually(() =>
    desktopShell.current.scenario === "chat-draft"
    && desktopShell.current.productSurfacePresent
    && desktopShell.current.sessionHeading === "Sessions"
    && desktopShell.current.mainNavigationPresent
    && desktopShell.current.newPaneControlPresent
  ).within(10, "seconds"),
);
