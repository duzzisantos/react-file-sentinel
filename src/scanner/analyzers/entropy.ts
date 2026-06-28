import type { Threat } from "../../types";

export function calculateEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;

  const freq = new Array<number>(256).fill(0);
  for (let i = 0; i < data.length; i++) {
    freq[data[i]]++;
  }

  let entropy = 0;
  const len = data.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export function analyzeEntropy(
  data: Uint8Array,
  fileName: string,
): { entropy: number; threats: Threat[] } {
  const threats: Threat[] = [];
  const entropy = calculateEntropy(data);
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();

  const isCompressed = [".zip", ".gz", ".7z", ".rar", ".docx", ".xlsx", ".pptx"].includes(ext);
  const isMedia = [".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4", ".wav", ".avi", ".mov"].includes(ext);

  if (entropy > 7.9 && !isCompressed && !isMedia) {
    threats.push({
      category: "entropy_anomaly",
      severity: "high",
      description: `Extremely high entropy (${entropy.toFixed(3)}/8.0) suggests encrypted or packed content — possible obfuscated payload.`,
    });
  } else if (entropy > 7.5 && !isCompressed && !isMedia) {
    threats.push({
      category: "entropy_anomaly",
      severity: "medium",
      description: `High entropy (${entropy.toFixed(3)}/8.0) — file may contain encrypted or compressed regions.`,
    });
  }

  if (entropy < 0.5 && data.length > 1024) {
    threats.push({
      category: "entropy_anomaly",
      severity: "low",
      description: `Very low entropy (${entropy.toFixed(3)}/8.0) — file appears to contain mostly repeated or null bytes.`,
    });
  }

  return { entropy, threats };
}
