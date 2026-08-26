export const HRA_READING_REVIEW_LABEL = "August 26, 2026" as const;
export const HRA_HEADLONG_READING_SLUG = "headlong-always-on-loop" as const;
export const HRA_HEADLONG_READING_PATH =
  `/reading/${HRA_HEADLONG_READING_SLUG}` as const;
export const HRA_HEADLONG_READING_TITLE =
  "Headlong's always-on loop next to HRA v0" as const;
export const HRA_HEADLONG_READING_DESCRIPTION =
  "Laude's Headlong keeps one agent thinking between messages. HRA v0's published job is a Codex metaharness around durable parent and child work." as const;

export const HRA_HEADLONG_READING_SOURCE =
  "https://hraness.com/reading/headlong-a-microharness-for-persistent-agents" as const;
export const HRA_HEADLONG_ORIGINAL_SOURCE =
  "https://www.laude.org/updates/headlong-a-microharness-for-persistent-agents" as const;
export const HRA_HARNESS_WRITING_SOURCE =
  "https://hraness.com/writing/what-is-an-agent-harness" as const;

function canonicalPublicPath(pathname: string): string {
  return pathname.length > 1 && pathname.endsWith("/")
    ? pathname.slice(0, -1)
    : pathname;
}

export function isHraPublicReadingPath(pathname: string): boolean {
  return canonicalPublicPath(pathname) === HRA_HEADLONG_READING_PATH;
}

export const headlongReadingCopy = {
  eyebrow: "Reading take",
  heading: `${HRA_HEADLONG_READING_TITLE}.`,
  lede: HRA_HEADLONG_READING_DESCRIPTION,
  reviewed: `Sources fetched ${HRA_READING_REVIEW_LABEL}.`,
  headlongHeading: "Headlong's job is one always-on stream",
  headlongBody: [
    "Laude Institute and MIT published Headlong as an open-source Bash microharness for persistent agency. The core is under 10K lines of Bash around shellm. The agent keeps thinking between human messages in a self-guided loop. Incoming chat lands as an observation in one thought stream rather than starting a session, and the agent decides if and when to reply.",
    "Most harnesses in that account are reactive: they work a task, then sit frozen. Some add cron or heartbeats that wake the agent to run a fixed checklist. Headlong's published contrast is that the agent is never asleep, and there is no checklist unless the agent creates one. Audel, Laude's shared agent, runs that one stream across Slack, Telegram, and a mobile app.",
    "One stream is also a boundary. There are no per-user sessions and no hard walls between people. Continuous thought costs $1 to $2 an hour at the settings Laude reports for GLM or Grok. The install guidance is a sandbox plus a spend-capped key.",
  ],
  hraHeading: "HRA v0's job is a Codex metaharness",
  hraBody: [
    "A harness runs an agent. A metaharness decides how several harnesses divide work, share bounded context, choose a lane, recover interrupted effects, and bring results back to one review path. The live HRA v0 archive publishes that job: coordinate authorized Codex accounts, keep a durable parent-and-child task graph, and recover the work after a restart instead of only restoring a window.",
    "The Hraness essay that names the agent harness says Hra is the loop. The live page is a Codex metaharness that coordinates parallel sessions: parent and child tasks, review, and recovery after a window dies. The model still chooses the next tool call. Hra keeps the work from vanishing when the chat does. That essay also says each host should keep the page that is native to its surface.",
    "HRA v0's published fit is several coordinated Codex sessions, isolated authorized accounts, child work that rejoins a durable parent, and explicit recovery for restarts and ambiguous effects. Execution authority stays on the paired Mac. The hosted surface receives bounded coordination and review state.",
  ],
  contrastHeading: "The jobs sit next to each other",
  contrastBody: [
    "Headlong's published job is to keep one named agent thinking. Messages are observations in a single mind. HRA v0's published job is to keep several Codex harnesses attached to one review path after a chat or window ends.",
    "Those are different loops. Headlong's loop is the agent's inner monologue. HRA v0's loop is the coordination around parallel Codex sessions. Headlong's design shares one timeline across every conversation. HRA v0's design isolates authorized Codex accounts and keeps credentials, repositories, and provider sessions on the Mac.",
    "This page does not claim that Headlong cannot coordinate work, or that HRA v0 cannot run continuously. It only contrasts the jobs the fetched pages actually state.",
  ],
} as const;

export function createHeadlongReadingMarkdown(origin: string): string {
  const absoluteUrl = (path: `/${string}`): string => `${origin}${path}`;
  return [
    `# ${headlongReadingCopy.heading}`,
    "",
    headlongReadingCopy.lede,
    "",
    headlongReadingCopy.reviewed,
    "",
    `## ${headlongReadingCopy.headlongHeading}`,
    "",
    ...headlongReadingCopy.headlongBody.flatMap((paragraph) => [paragraph, ""]),
    `## ${headlongReadingCopy.hraHeading}`,
    "",
    ...headlongReadingCopy.hraBody.flatMap((paragraph) => [paragraph, ""]),
    `## ${headlongReadingCopy.contrastHeading}`,
    "",
    ...headlongReadingCopy.contrastBody.flatMap((paragraph) => [paragraph, ""]),
    "## Sources",
    "",
    `- [Headlong reading digest](${HRA_HEADLONG_READING_SOURCE})`,
    `- [Headlong: a microharness for persistent agents](${HRA_HEADLONG_ORIGINAL_SOURCE})`,
    `- [What is an agent harness?](${HRA_HARNESS_WRITING_SOURCE})`,
    `- [HRA v0 archive](${absoluteUrl("/")})`,
    "",
    "## Public pages",
    "",
    `- [HRA v0 archive](${absoluteUrl("/")})`,
    `- [Compare HRA](${absoluteUrl("/alternatives")})`,
    `- [Agent guide](${absoluteUrl("/llms.txt")})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    "",
  ].join("\n");
}
