import type { Threat } from "../../types";

const ZIP_BOMB_RATIO_THRESHOLD = 100;
const MAX_NESTED_DEPTH_WARNING = 3;

function countZipEntries(data: Uint8Array): number {
  let count = 0;
  const localHeader = [0x50, 0x4b, 0x03, 0x04];
  for (let i = 0; i <= data.length - 4; i++) {
    if (
      data[i] === localHeader[0] &&
      data[i + 1] === localHeader[1] &&
      data[i + 2] === localHeader[2] &&
      data[i + 3] === localHeader[3]
    ) {
      count++;
    }
  }
  return count;
}

function readUint32LE(data: Uint8Array, offset: number): number {
  return (
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24)
  ) >>> 0;
}

function estimateUncompressedSize(data: Uint8Array): number {
  let totalUncompressed = 0;
  const localHeader = [0x50, 0x4b, 0x03, 0x04];

  for (let i = 0; i <= data.length - 30; i++) {
    if (
      data[i] === localHeader[0] &&
      data[i + 1] === localHeader[1] &&
      data[i + 2] === localHeader[2] &&
      data[i + 3] === localHeader[3]
    ) {
      totalUncompressed += readUint32LE(data, i + 22);
    }
  }
  return totalUncompressed;
}

export function analyzeStructure(
  data: Uint8Array,
  fileName: string,
  detectedMime: string,
): { threats: Threat[]; structureValid: boolean; hasEmbeddedFiles: boolean } {
  const threats: Threat[] = [];
  let structureValid = true;
  let hasEmbeddedFiles = false;
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();

  const isZip =
    detectedMime === "application/zip" ||
    [".zip", ".docx", ".xlsx", ".pptx"].includes(ext);

  if (isZip && data.length >= 4) {
    const entryCount = countZipEntries(data);
    hasEmbeddedFiles = entryCount > 1;

    if (entryCount > 10000) {
      threats.push({
        category: "zip_bomb",
        severity: "critical",
        description: `Archive contains ${entryCount.toLocaleString()} entries — likely a zip bomb (file count decompression attack).`,
      });
      structureValid = false;
    }

    const estimated = estimateUncompressedSize(data);
    if (estimated > 0 && data.length > 0) {
      const ratio = estimated / data.length;
      if (ratio > ZIP_BOMB_RATIO_THRESHOLD) {
        threats.push({
          category: "zip_bomb",
          severity: "critical",
          description: `Compression ratio ${ratio.toFixed(0)}:1 exceeds safe threshold — possible zip bomb.`,
        });
        structureValid = false;
      }
    }

    if (entryCount > MAX_NESTED_DEPTH_WARNING * 100) {
      threats.push({
        category: "zip_bomb",
        severity: "high",
        description: `Unusually high number of nested entries (${entryCount}) — may be a decompression attack.`,
      });
    }
  }

  if (data.length === 0) {
    threats.push({
      category: "suspicious_metadata",
      severity: "low",
      description: "File is empty (0 bytes).",
    });
    structureValid = false;
  }

  return { threats, structureValid, hasEmbeddedFiles };
}
