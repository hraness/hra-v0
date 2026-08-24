import type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  parseCanonicalMacOSCustodyStatus,
} from "./macos-custody-probe";
import {
  runMacOSResidentCustodyProbe,
  type MacOSResidentCustodyProbeInput,
  type MacOSResidentCustodyProbeResult,
} from "./macos-resident-custody-probe";

export type ResidentEnrollmentCustodyObservation =
  | Readonly<{ state: "absent" }>
  | Readonly<{
      envelopeSha256: string;
      state: "present";
      strictAcl: true;
    }>;

export interface ResidentCustodyProbeAdapterDependencies {
  readonly run: (
    input: MacOSResidentCustodyProbeInput,
  ) => MacOSResidentCustodyProbeResult | Promise<MacOSResidentCustodyProbeResult>;
}

export const defaultResidentCustodyProbeAdapterDependencies = Object.freeze({
  run: runMacOSResidentCustodyProbe,
} satisfies ResidentCustodyProbeAdapterDependencies);

function requireExactSuccessfulResult(
  result: MacOSResidentCustodyProbeResult,
): void {
  if (result.exitCode !== 0 || result.stderr !== "") {
    throw new Error("Resident custody probe did not return exact success.");
  }
}

export async function inspectResidentEnrollmentCustodyNoUi(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: ResidentCustodyProbeAdapterDependencies =
    defaultResidentCustodyProbeAdapterDependencies,
): Promise<ResidentEnrollmentCustodyObservation> {
  const result = await dependencies.run({
    authority,
    candidateApp,
    mode: "status",
  });
  requireExactSuccessfulResult(result);
  const status = parseCanonicalMacOSCustodyStatus(result.stdout);
  return status.state === "absent"
    ? Object.freeze({ state: "absent" })
    : Object.freeze({
        envelopeSha256: status.envelopeSha256,
        state: "present",
        strictAcl: true,
      });
}

export async function authorizeResidentCustodyCandidate(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  expectedStdout: string,
  dependencies: ResidentCustodyProbeAdapterDependencies =
    defaultResidentCustodyProbeAdapterDependencies,
): Promise<void> {
  const result = await dependencies.run({
    authority,
    candidateApp,
    expectedStdout,
    mode: "authorize",
  });
  requireExactSuccessfulResult(result);
  if (result.stdout !== expectedStdout) {
    throw new Error("Resident authorize-only receipt differs from its expectation.");
  }
}

export async function smokeResidentCustodyCandidate(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  smokeRoot: string,
  dwellMilliseconds: number,
  dependencies: ResidentCustodyProbeAdapterDependencies =
    defaultResidentCustodyProbeAdapterDependencies,
): Promise<void> {
  const result = await dependencies.run({
    authority,
    candidateApp,
    dwellMilliseconds,
    mode: "smoke",
    smokeRoot,
  });
  requireExactSuccessfulResult(result);
  if (result.stdout !== "") {
    throw new Error("Resident smoke probe emitted unexpected output.");
  }
}
