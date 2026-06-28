import type { Threat } from "../../types";

interface MagicSignature {
  bytes: number[];
  offset: number;
  mime: string;
  extension: string;
}

const SIGNATURES: MagicSignature[] = [
  { bytes: [0x25, 0x50, 0x44, 0x46], offset: 0, mime: "application/pdf", extension: ".pdf" },
  { bytes: [0x89, 0x50, 0x4e, 0x47], offset: 0, mime: "image/png", extension: ".png" },
  { bytes: [0xff, 0xd8, 0xff], offset: 0, mime: "image/jpeg", extension: ".jpg" },
  { bytes: [0x47, 0x49, 0x46, 0x38], offset: 0, mime: "image/gif", extension: ".gif" },
  { bytes: [0x42, 0x4d], offset: 0, mime: "image/bmp", extension: ".bmp" },
  { bytes: [0x52, 0x49, 0x46, 0x46], offset: 0, mime: "image/webp", extension: ".webp" },
  { bytes: [0x50, 0x4b, 0x03, 0x04], offset: 0, mime: "application/zip", extension: ".zip" },
  { bytes: [0x50, 0x4b, 0x05, 0x06], offset: 0, mime: "application/zip", extension: ".zip" },
  { bytes: [0x1f, 0x8b], offset: 0, mime: "application/gzip", extension: ".gz" },
  { bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], offset: 0, mime: "application/x-7z-compressed", extension: ".7z" },
  { bytes: [0x52, 0x61, 0x72, 0x21], offset: 0, mime: "application/x-rar-compressed", extension: ".rar" },
  { bytes: [0x49, 0x44, 0x33], offset: 0, mime: "audio/mpeg", extension: ".mp3" },
  { bytes: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [0x00, 0x00, 0x00, 0x1c, 0x66, 0x74, 0x79, 0x70], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], offset: 0, mime: "application/x-ole-storage", extension: ".doc" },
  // Executable formats (always suspicious in form uploads)
  { bytes: [0x4d, 0x5a], offset: 0, mime: "application/x-msdownload", extension: ".exe" },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], offset: 0, mime: "application/x-elf", extension: ".elf" },
];

const EXECUTABLE_MIMES = new Set([
  "application/x-msdownload",
  "application/x-elf",
  "application/x-mach-binary",
  "application/x-executable",
]);

const OOXML_MIMES: Record<string, string> = {
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

export function detectMimeType(header: Uint8Array): string {
  for (const sig of SIGNATURES) {
    if (header.length < sig.offset + sig.bytes.length) continue;
    const match = sig.bytes.every(
      (b, i) => header[sig.offset + i] === b,
    );
    if (match) return sig.mime;
  }
  return "application/octet-stream";
}

export function getMagicBytesHex(header: Uint8Array): string {
  return Array.from(header.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
}

export function analyzeFileType(
  header: Uint8Array,
  declaredMime: string,
  fileName: string,
): { detectedMime: string; threats: Threat[]; hasExecutable: boolean } {
  const threats: Threat[] = [];
  const detectedMime = detectMimeType(header);
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();

  const isExecutable = EXECUTABLE_MIMES.has(detectedMime);
  if (isExecutable) {
    threats.push({
      category: "malware_signature",
      severity: "critical",
      description: `Executable binary detected (${detectedMime}). Executables are not safe for form uploads.`,
      signature: getMagicBytesHex(header),
    });
  }

  const isOoxml = ext in OOXML_MIMES;
  if (isOoxml && detectedMime === "application/zip") {
    return { detectedMime: OOXML_MIMES[ext], threats, hasExecutable: isExecutable };
  }

  if (
    detectedMime !== "application/octet-stream" &&
    declaredMime !== detectedMime &&
    !isOoxml
  ) {
    const isDangerous =
      EXECUTABLE_MIMES.has(detectedMime) ||
      (declaredMime.startsWith("image/") && !detectedMime.startsWith("image/"));

    threats.push({
      category: "file_type_mismatch",
      severity: isDangerous ? "high" : "medium",
      description: `File claims to be ${declaredMime} but magic bytes indicate ${detectedMime}.`,
      signature: getMagicBytesHex(header),
    });
  }

  return { detectedMime, threats, hasExecutable: isExecutable };
}
