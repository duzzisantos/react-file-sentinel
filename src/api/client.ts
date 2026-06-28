import type { ScanReport, ScanAPIPayload, ScanAPIResponse, ScanVerdict } from "../types";

function generateSessionId(): string {
  return `sess_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function deriveOverallVerdict(reports: ScanReport[]): ScanVerdict {
  if (reports.some((r) => r.verdict === "malicious")) return "malicious";
  if (reports.some((r) => r.verdict === "suspicious")) return "suspicious";
  return "clean";
}

export function buildPayload(
  reports: ScanReport[],
  clientId: string,
): ScanAPIPayload {
  return {
    reports,
    clientId,
    sessionId: generateSessionId(),
    timestamp: new Date().toISOString(),
    totalFiles: reports.length,
    totalThreats: reports.reduce((sum, r) => sum + r.threats.length, 0),
    overallVerdict: deriveOverallVerdict(reports),
  };
}

export async function submitScanReport(
  endpoint: string,
  reports: ScanReport[],
  clientId: string,
): Promise<ScanAPIResponse> {
  const payload = buildPayload(reports, clientId);

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Sentinel-Version": reports[0]?.engineVersion ?? "unknown",
      "X-Sentinel-Client": clientId,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(
      `Sentinel API error: ${response.status} ${response.statusText}`,
    );
  }

  return response.json();
}
