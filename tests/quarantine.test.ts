import { describe, it, expect } from "vitest";
import { Quarantine } from "../src/scanner/quarantine";
import type { ScanReport } from "../src/types";

function mockReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    id: `scan_${Math.random().toString(36).slice(2)}`,
    fileName: "test.pdf",
    fileSize: 1024,
    scanStartedAt: new Date().toISOString(),
    scanCompletedAt: new Date().toISOString(),
    scanDurationMs: 10,
    threats: [],
    riskScore: 50,
    verdict: "suspicious",
    metadata: {
      declaredMimeType: "application/pdf",
      detectedMimeType: "application/pdf",
      magicBytes: "25 50 44 46",
      extension: ".pdf",
      sha256: "abc123",
      entropy: 5.0,
      hasEmbeddedFiles: false,
      hasExecutableContent: false,
      structureValid: true,
    },
    quarantine: { status: "held", reason: "Suspicious" },
    engineVersion: "1.0.0",
    ...overrides,
  };
}

describe("Quarantine", () => {
  it("adds and retrieves files", () => {
    const q = new Quarantine();
    const file = new File(["content"], "test.pdf");
    const report = mockReport();

    q.add(file, report);
    expect(q.size).toBe(1);
    expect(q.get(report.id)).toBeDefined();
    expect(q.getReport(report.id)?.fileName).toBe("test.pdf");
  });

  it("releases files from quarantine", () => {
    const q = new Quarantine();
    const file = new File(["content"], "test.pdf");
    const report = mockReport();

    q.add(file, report);
    const released = q.release(report.id);

    expect(released).toBe(file);
    expect(q.size).toBe(0);
    expect(report.quarantine.status).toBe("released");
  });

  it("destroys files permanently", () => {
    const q = new Quarantine();
    const file = new File(["content"], "test.pdf");
    const report = mockReport();

    q.add(file, report);
    const destroyed = q.destroy(report.id);

    expect(destroyed).toBe(true);
    expect(q.size).toBe(0);
    expect(report.quarantine.status).toBe("destroyed");
  });

  it("returns null when releasing non-existent file", () => {
    const q = new Quarantine();
    expect(q.release("nonexistent")).toBeNull();
  });

  it("returns false when destroying non-existent file", () => {
    const q = new Quarantine();
    expect(q.destroy("nonexistent")).toBe(false);
  });

  it("clears all quarantined files", () => {
    const q = new Quarantine();
    const report1 = mockReport();
    const report2 = mockReport();

    q.add(new File(["a"], "a.pdf"), report1);
    q.add(new File(["b"], "b.pdf"), report2);

    expect(q.size).toBe(2);
    q.clear();
    expect(q.size).toBe(0);
    expect(report1.quarantine.status).toBe("destroyed");
    expect(report2.quarantine.status).toBe("destroyed");
  });

  it("lists all quarantined files", () => {
    const q = new Quarantine();
    q.add(new File(["a"], "a.pdf"), mockReport({ id: "1" }));
    q.add(new File(["b"], "b.pdf"), mockReport({ id: "2" }));

    const all = q.getAll();
    expect(all).toHaveLength(2);
  });
});
