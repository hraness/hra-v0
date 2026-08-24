import { describe, expect, test } from "bun:test";

import type {
  MacOSResidentCustodyProbeInput,
  MacOSResidentCustodyProbeResult,
} from "../macos-resident-custody-probe";
import {
  authorizeResidentCustodyCandidate,
  inspectResidentEnrollmentCustodyNoUi,
  smokeResidentCustodyCandidate,
  type ResidentCustodyProbeAdapterDependencies,
} from "../resident-custody-probe-adapter";
import { testCustodyProbeSupervisorAuthority } from
  "./fixtures/custody-probe-authority";
import { defaultForwardRecoveryDependencies } from
  "../installation-forward-recovery";

const candidateApp = "/Applications/HRA candidate.app";
const expectedAuthorization =
  `{"authorization":"hra-parent-v1","gatewayFileSha256":"${"1".repeat(64)}",` +
  `"keychainAccessed":false,"ok":true,"rendererAuthoritySha256":"${"2".repeat(64)}",` +
  "\"version\":1}\n";

function injectedAdapter(
  result: Readonly<{ exitCode: number; stderr: string; stdout: string }>,
): Readonly<{
  calls: MacOSResidentCustodyProbeInput[];
  dependencies: ResidentCustodyProbeAdapterDependencies;
}> {
  const calls: MacOSResidentCustodyProbeInput[] = [];
  return Object.freeze({
    calls,
    dependencies: Object.freeze({
      run(input: MacOSResidentCustodyProbeInput) {
        calls.push(input);
        return result as MacOSResidentCustodyProbeResult;
      },
    }),
  });
}

describe("resident custody probe production adapter", () => {
  test("is the fail-closed default for forward-recovery custody inspection", () => {
    expect(defaultForwardRecoveryDependencies.inspectEnrollmentKeychainNoUi)
      .toBe(inspectResidentEnrollmentCustodyNoUi);
  });

  test("forwards exact candidate authority and strips only the native status version", async () => {
    for (const [stdout, expected] of [
      [
        "{\"schemaVersion\":1,\"state\":\"absent\"}\n",
        { state: "absent" },
      ],
      [
        `{"envelopeSha256":"${"3".repeat(64)}","schemaVersion":1,` +
          "\"state\":\"present\",\"strictAcl\":true}\n",
        {
          envelopeSha256: "3".repeat(64),
          state: "present",
          strictAcl: true,
        },
      ],
    ] as const) {
      const adapter = injectedAdapter({ exitCode: 0, stderr: "", stdout });
      expect(await inspectResidentEnrollmentCustodyNoUi(
        candidateApp,
        testCustodyProbeSupervisorAuthority,
        adapter.dependencies,
      )).toEqual(expected);
      expect(adapter.calls).toEqual([{
        authority: testCustodyProbeSupervisorAuthority,
        candidateApp,
        mode: "status",
      }]);
      expect(adapter.calls[0]!.authority)
        .toBe(testCustodyProbeSupervisorAuthority);
    }
  });

  test("rejects status substitution instead of widening the strict driver shape", () => {
    for (const result of [
      { exitCode: 0, stderr: "", stdout: "{\"schemaVersion\":2,\"state\":\"absent\"}\n" },
      { exitCode: 0, stderr: "residue", stdout: "{\"schemaVersion\":1,\"state\":\"absent\"}\n" },
      { exitCode: 1, stderr: "", stdout: "{\"schemaVersion\":1,\"state\":\"absent\"}\n" },
    ] as const) {
      const adapter = injectedAdapter(result);
      expect(inspectResidentEnrollmentCustodyNoUi(
        candidateApp,
        testCustodyProbeSupervisorAuthority,
        adapter.dependencies,
      )).rejects.toThrow();
    }
  });

  test("binds authorize-only output to the exact receipt and candidate authority", async () => {
    const adapter = injectedAdapter({
      exitCode: 0,
      stderr: "",
      stdout: expectedAuthorization,
    });
    await authorizeResidentCustodyCandidate(
      candidateApp,
      testCustodyProbeSupervisorAuthority,
      expectedAuthorization,
      adapter.dependencies,
    );
    expect(adapter.calls).toEqual([{
      authority: testCustodyProbeSupervisorAuthority,
      candidateApp,
      expectedStdout: expectedAuthorization,
      mode: "authorize",
    }]);
    expect(adapter.calls[0]!.authority).toBe(testCustodyProbeSupervisorAuthority);

    const substitution = injectedAdapter({
      exitCode: 0,
      stderr: "",
      stdout: expectedAuthorization.replace("1".repeat(64), "4".repeat(64)),
    });
    expect(authorizeResidentCustodyCandidate(
      candidateApp,
      testCustodyProbeSupervisorAuthority,
      expectedAuthorization,
      substitution.dependencies,
    )).rejects.toThrow("receipt differs");
  });

  test("passes the exact smoke root and rejects all output residue", async () => {
    const adapter = injectedAdapter({ exitCode: 0, stderr: "", stdout: "" });
    await smokeResidentCustodyCandidate(
      candidateApp,
      testCustodyProbeSupervisorAuthority,
      "/private/tmp/hra-resident-smoke",
      8_000,
      adapter.dependencies,
    );
    expect(adapter.calls).toEqual([{
      authority: testCustodyProbeSupervisorAuthority,
      candidateApp,
      dwellMilliseconds: 8_000,
      mode: "smoke",
      smokeRoot: "/private/tmp/hra-resident-smoke",
    }]);

    for (const result of [
      { exitCode: 0, stderr: "residue", stdout: "" },
      { exitCode: 0, stderr: "", stdout: "residue" },
    ] as const) {
      expect(smokeResidentCustodyCandidate(
        candidateApp,
        testCustodyProbeSupervisorAuthority,
        "/private/tmp/hra-resident-smoke",
        8_000,
        injectedAdapter(result).dependencies,
      )).rejects.toThrow();
    }
  });
});
