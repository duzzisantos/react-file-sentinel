import type { ScanReport, Threat, FileMetadata, ScanVerdict, ENGINE_VERSION as EV } from "../types";
import { ENGINE_VERSION } from "../types";
import { analyzeFileType, getMagicBytesHex } from "./analyzers/magic-bytes";
import { analyzeEntropy } from "./analyzers/entropy";
import { analyzeMacros } from "./analyzers/macro-detector";
import { analyzeScripts } from "./analyzers/script-detector";
import { analyzePolyglot } from "./analyzers/polyglot";
import { analyzeStructure } from "./analyzers/structure";

async function computeSha256(data: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(data);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateId(): string {
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function computeRiskScore(threats: Threat[]): number {
  const weights: Record<string, number> = {
    critical: 40,
    high: 25,
    medium: 12,
    low: 5,
    info: 1,
  };

  let score = 0;
  for (const t of threats) {
    score += weights[t.severity] ?? 0;
  }
  return Math.min(score, 100);
}

function deriveVerdict(riskScore: number, threats: Threat[]): ScanVerdict {
  const hasCritical = threats.some((t) => t.severity === "critical");
  if (hasCritical || riskScore >= 70) return "malicious";
  if (riskScore >= 30) return "suspicious";
  return "clean";
}

export async function scanFile(
  file: File,
  maxSizeMB: number = 100,
): Promise<ScanReport> {
  const startTime = performance.now();
  const id = generateId();
  const allThreats: Threat[] = [];

  if (file.size > maxSizeMB * 1024 * 1024) {
    allThreats.push({
      category: "oversized_file",
      severity: "medium",
      description: `File size (${(file.size / 1024 / 1024).toFixed(1)} MB) exceeds ${maxSizeMB} MB limit.`,
    });
  }

  const buffer = await file.arrayBuffer();
  const data = new Uint8Array(buffer);
  const sha256 = await computeSha256(buffer);

  const header = data.slice(0, 64);
  const { detectedMime, threats: typeThreats, hasExecutable } = analyzeFileType(
    header,
    file.type,
    file.name,
  );
  allThreats.push(...typeThreats);

  const { entropy, threats: entropyThreats } = analyzeEntropy(data, file.name);
  allThreats.push(...entropyThreats);

  const { threats: macroThreats, hasMacros } = analyzeMacros(data, file.name);
  allThreats.push(...macroThreats);

  const { threats: scriptThreats, hasScripts } = analyzeScripts(
    data,
    file.name,
    detectedMime,
  );
  allThreats.push(...scriptThreats);

  const { threats: polyglotThreats } = analyzePolyglot(
    data,
    file.name,
    detectedMime,
  );
  allThreats.push(...polyglotThreats);

  const { threats: structureThreats, structureValid, hasEmbeddedFiles } =
    analyzeStructure(data, file.name, detectedMime);
  allThreats.push(...structureThreats);

  const riskScore = computeRiskScore(allThreats);
  const verdict = deriveVerdict(riskScore, allThreats);
  const endTime = performance.now();

  const metadata: FileMetadata = {
    declaredMimeType: file.type || "unknown",
    detectedMimeType: detectedMime,
    magicBytes: getMagicBytesHex(header),
    extension: file.name.slice(file.name.lastIndexOf(".")).toLowerCase(),
    sha256,
    entropy,
    hasEmbeddedFiles,
    hasExecutableContent: hasExecutable || hasScripts || hasMacros,
    structureValid,
  };

  return {
    id,
    fileName: file.name,
    fileSize: file.size,
    scanStartedAt: new Date(Date.now() - (endTime - startTime)).toISOString(),
    scanCompletedAt: new Date().toISOString(),
    scanDurationMs: Math.round(endTime - startTime),
    threats: allThreats,
    riskScore,
    verdict,
    metadata,
    quarantine: {
      status: verdict === "clean" ? "released" : "held",
      reason: verdict !== "clean" ? `Risk score ${riskScore}/100 — ${verdict}` : null,
    },
    engineVersion: ENGINE_VERSION,
  };
}
