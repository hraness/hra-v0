import { expect, test } from "bun:test";
import { fc } from "@hra-internal/test";

import { parseForwardRecoveryReceipt } from "../installation-forward-recovery";
import { forwardReceiptFixture } from "./installation-forward-recovery-schema.test";

test("forward receipt accepts exactly the legal phase and Keychain-status products", () => {
  const phases = [
    "authorizing",
    "prepared",
    "published",
    "verified",
    "complete",
    "aborted",
  ] as const;
  const statuses = [
    "pending_same_process",
    "verified_same_process",
    "unavailable_after_process_restart",
    "not_applicable",
  ] as const;
  fc.assert(fc.property(
    fc.constantFrom(...phases),
    fc.constantFrom(...statuses),
    (phase, keychainContinuity) => {
      const legal = (
        ((phase === "authorizing" || phase === "prepared" || phase === "published")
          && (keychainContinuity === "pending_same_process"
            || keychainContinuity === "unavailable_after_process_restart"))
        || (phase === "verified" && keychainContinuity === "verified_same_process")
        || (phase === "complete"
          && (keychainContinuity === "verified_same_process"
            || keychainContinuity === "unavailable_after_process_restart"))
        || (phase === "aborted" && keychainContinuity === "not_applicable")
      );
      const fixture = forwardReceiptFixture();
      const preEnrollment = phase === "authorizing" || phase === "aborted";
      const parse = () => parseForwardRecoveryReceipt({
        ...fixture,
        phase,
        keychainContinuity,
        ...(preEnrollment
          ? {
              state: fixture["preState"],
              enrollment: {
                ...(fixture["enrollment"] as object),
                file: null,
              },
            }
          : {}),
      });
      if (legal) expect(parse).not.toThrow();
      else expect(parse).toThrow();
    },
  ));
});

test("foreign vnode encodings never enter the bigint receipt boundary", () => {
  fc.assert(fc.property(
    fc.oneof(
      fc.integer(),
      fc.string().filter(value => !/^(?:0|[1-9][0-9]*)$/u.test(value)),
    ),
    device => {
      const receipt = forwardReceiptFixture();
      receipt["origin"] = {
        ...(receipt["origin"] as object),
        root: {
          ...((receipt["origin"] as Record<string, unknown>)["root"] as object),
          device,
        },
      };
      expect(() => parseForwardRecoveryReceipt(receipt)).toThrow();
    },
  ));
});

test("arbitrary nested receipt fields fail the strict forward schema", () => {
  fc.assert(fc.property(
    fc.string({ minLength: 1, maxLength: 40 }).filter(key => ![
      "bytes",
      "directories",
      "digest",
      "entries",
      "files",
      "symlinks",
    ].includes(key)),
    fc.jsonValue(),
    (key, value) => {
      const receipt = forwardReceiptFixture();
      const candidate = receipt["candidate"] as Record<string, unknown>;
      const bundle = candidate["bundle"] as Record<string, unknown>;
      candidate["bundle"] = {
        ...bundle,
        tree: {
          ...(bundle["tree"] as object),
          [key]: value,
        },
      };
      expect(() => parseForwardRecoveryReceipt(receipt)).toThrow();
    },
  ));
});
