import type { Threat } from "../../types";

const SECONDARY_SIGNATURES: Array<{
  bytes: number[];
  name: string;
}> = [
  { bytes: [0x4d, 0x5a], name: "PE executable" },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], name: "ELF binary" },
  { bytes: [0x50, 0x4b, 0x03, 0x04], name: "ZIP archive" },
  { bytes: [0x25, 0x50, 0x44, 0x46], name: "PDF document" },
  { bytes: [0x52, 0x61, 0x72, 0x21], name: "RAR archive" },
];

function findSignatureAt(data: Uint8Array, offset: number): string | null {
  for (const sig of SECONDARY_SIGNATURES) {
    if (offset + sig.bytes.length > data.length) continue;
    const match = sig.bytes.every((b, i) => data[offset + i] === b);
    if (match) return sig.name;
  }
  return null;
}

export function analyzePolyglot(
  data: Uint8Array,
  fileName: string,
  primaryMime: string,
): { threats: Threat[]; isPolyglot: boolean } {
  const threats: Threat[] = [];
  let isPolyglot = false;

  const scanOffsets = [
    512,
    1024,
    4096,
    Math.floor(data.length / 2),
    data.length > 1024 ? data.length - 1024 : -1,
  ].filter((o) => o > 0 && o < data.length);

  for (const offset of scanOffsets) {
    const found = findSignatureAt(data, offset);
    if (found) {
      const primaryType = primaryMime.split("/").pop() || primaryMime;
      if (!found.toLowerCase().includes(primaryType)) {
        isPolyglot = true;
        threats.push({
          category: "polyglot_file",
          severity: "critical",
          description: `Polyglot file: appears to be ${primaryMime} but contains embedded ${found} at offset ${offset}. This is a common malware evasion technique.`,
          location: `byte offset ${offset}`,
          signature: found,
        });
      }
    }
  }

  return { threats, isPolyglot };
}
