import { describe, it, expect } from "vitest";
import { buildPayload } from "../src/api/client";
import type { ScanReport } from "../src/types";

function mockReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    id: "scan_test_123",
    fileName: "test.pdf",
    fileSize: 1024,
    scanStartedAt: new Date().toISOString(),
    scanCompletedAt: new Date().toISOString(),
    scanDurationMs: 10,
    threats: [
      {
        category: "script_injection",
        severity: "high",
        description: "JavaScript in PDF",
      },
    ],
    riskScore: 45,
    verdict: "suspicious",
    metadata: {
      declaredMimeType: "application/pdf",
      detectedMimeType: "application/pdf",
      magicBytes: "25 50 44 46",
      extension: ".pdf",
      sha256: "abc123def456",
      entropy: 6.2,
      hasEmbeddedFiles: false,
      hasExecutableContent: true,
      structureValid: true,
    },
    quarantine: { status: "held", reason: "Suspicious" },
    engineVersion: "1.0.0",
    ...overrides,
  };
}

describe("API client", () => {
  it("builds a valid payload from scan reports", () => {
    const reports = [mockReport(), mockReport({ id: "scan_test_456", verdict: "clean", threats: [] })];
    const payload = buildPayload(reports, "client_abc");

    expect(payload.clientId).toBe("client_abc");
    expect(payload.totalFiles).toBe(2);
    expect(payload.totalThreats).toBe(1);
    expect(payload.overallVerdict).toBe("suspicious");
    expect(payload.sessionId).toMatch(/^sess_/);
    expect(payload.timestamp).toBeTruthy();
    expect(payload.reports).toHaveLength(2);
  });

  it("returns malicious overall verdict if any file is malicious", () => {
    const reports = [
      mockReport({ verdict: "clean", threats: [] }),
      mockReport({ verdict: "malicious" }),
    ];
    const payload = buildPayload(reports, "client");
    expect(payload.overallVerdict).toBe("malicious");
  });

  it("returns clean if all files are clean", () => {
    const reports = [
      mockReport({ verdict: "clean", threats: [] }),
      mockReport({ verdict: "clean", threats: [] }),
    ];
    const payload = buildPayload(reports, "client");
    expect(payload.overallVerdict).toBe("clean");
  });
});
