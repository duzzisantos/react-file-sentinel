'use strict';

var react = require('react');
var jsxRuntime = require('react/jsx-runtime');

// src/hooks/useFileScanner.ts

// src/types/index.ts
var ENGINE_VERSION = "1.0.0";
var SUPPORTED_EXTENSIONS = [
  ".pdf",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".bmp",
  ".webp",
  ".svg",
  ".docx",
  ".xlsx",
  ".pptx",
  ".doc",
  ".xls",
  ".ppt",
  ".odt",
  ".ods",
  ".odp",
  ".rtf",
  ".txt",
  ".csv",
  ".zip",
  ".tar",
  ".gz",
  ".7z",
  ".rar",
  ".mp3",
  ".mp4",
  ".wav",
  ".avi",
  ".mov"
];

// src/scanner/analyzers/magic-bytes.ts
var SIGNATURES = [
  { bytes: [37, 80, 68, 70], offset: 0, mime: "application/pdf", extension: ".pdf" },
  { bytes: [137, 80, 78, 71], offset: 0, mime: "image/png", extension: ".png" },
  { bytes: [255, 216, 255], offset: 0, mime: "image/jpeg", extension: ".jpg" },
  { bytes: [71, 73, 70, 56], offset: 0, mime: "image/gif", extension: ".gif" },
  { bytes: [66, 77], offset: 0, mime: "image/bmp", extension: ".bmp" },
  { bytes: [82, 73, 70, 70], offset: 0, mime: "image/webp", extension: ".webp" },
  { bytes: [80, 75, 3, 4], offset: 0, mime: "application/zip", extension: ".zip" },
  { bytes: [80, 75, 5, 6], offset: 0, mime: "application/zip", extension: ".zip" },
  { bytes: [31, 139], offset: 0, mime: "application/gzip", extension: ".gz" },
  { bytes: [55, 122, 188, 175, 39, 28], offset: 0, mime: "application/x-7z-compressed", extension: ".7z" },
  { bytes: [82, 97, 114, 33], offset: 0, mime: "application/x-rar-compressed", extension: ".rar" },
  { bytes: [73, 68, 51], offset: 0, mime: "audio/mpeg", extension: ".mp3" },
  { bytes: [0, 0, 0, 24, 102, 116, 121, 112], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [0, 0, 0, 28, 102, 116, 121, 112], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [0, 0, 0, 32, 102, 116, 121, 112], offset: 0, mime: "video/mp4", extension: ".mp4" },
  { bytes: [208, 207, 17, 224, 161, 177, 26, 225], offset: 0, mime: "application/x-ole-storage", extension: ".doc" },
  // Executable formats (always suspicious in form uploads)
  { bytes: [77, 90], offset: 0, mime: "application/x-msdownload", extension: ".exe" },
  { bytes: [127, 69, 76, 70], offset: 0, mime: "application/x-elf", extension: ".elf" }
];
var EXECUTABLE_MIMES = /* @__PURE__ */ new Set([
  "application/x-msdownload",
  "application/x-elf",
  "application/x-mach-binary",
  "application/x-executable"
]);
var OOXML_MIMES = {
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"
};
function detectMimeType(header) {
  for (const sig of SIGNATURES) {
    if (header.length < sig.offset + sig.bytes.length) continue;
    const match = sig.bytes.every(
      (b, i) => header[sig.offset + i] === b
    );
    if (match) return sig.mime;
  }
  return "application/octet-stream";
}
function getMagicBytesHex(header) {
  return Array.from(header.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join(" ");
}
function analyzeFileType(header, declaredMime, fileName) {
  const threats = [];
  const detectedMime = detectMimeType(header);
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  const isExecutable = EXECUTABLE_MIMES.has(detectedMime);
  if (isExecutable) {
    threats.push({
      category: "malware_signature",
      severity: "critical",
      description: `Executable binary detected (${detectedMime}). Executables are not safe for form uploads.`,
      signature: getMagicBytesHex(header)
    });
  }
  const isOoxml = ext in OOXML_MIMES;
  if (isOoxml && detectedMime === "application/zip") {
    return { detectedMime: OOXML_MIMES[ext], threats, hasExecutable: isExecutable };
  }
  if (detectedMime !== "application/octet-stream" && declaredMime !== detectedMime && !isOoxml) {
    const isDangerous = EXECUTABLE_MIMES.has(detectedMime) || declaredMime.startsWith("image/") && !detectedMime.startsWith("image/");
    threats.push({
      category: "file_type_mismatch",
      severity: isDangerous ? "high" : "medium",
      description: `File claims to be ${declaredMime} but magic bytes indicate ${detectedMime}.`,
      signature: getMagicBytesHex(header)
    });
  }
  return { detectedMime, threats, hasExecutable: isExecutable };
}

// src/scanner/analyzers/entropy.ts
function calculateEntropy(data) {
  if (data.length === 0) return 0;
  const freq = new Array(256).fill(0);
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
function analyzeEntropy(data, fileName) {
  const threats = [];
  const entropy = calculateEntropy(data);
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  const isCompressed = [".zip", ".gz", ".7z", ".rar", ".docx", ".xlsx", ".pptx"].includes(ext);
  const isMedia = [".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4", ".wav", ".avi", ".mov"].includes(ext);
  if (entropy > 7.9 && !isCompressed && !isMedia) {
    threats.push({
      category: "entropy_anomaly",
      severity: "high",
      description: `Extremely high entropy (${entropy.toFixed(3)}/8.0) suggests encrypted or packed content \u2014 possible obfuscated payload.`
    });
  } else if (entropy > 7.5 && !isCompressed && !isMedia) {
    threats.push({
      category: "entropy_anomaly",
      severity: "medium",
      description: `High entropy (${entropy.toFixed(3)}/8.0) \u2014 file may contain encrypted or compressed regions.`
    });
  }
  if (entropy < 0.5 && data.length > 1024) {
    threats.push({
      category: "entropy_anomaly",
      severity: "low",
      description: `Very low entropy (${entropy.toFixed(3)}/8.0) \u2014 file appears to contain mostly repeated or null bytes.`
    });
  }
  return { entropy, threats };
}

// src/scanner/analyzers/macro-detector.ts
var OLE_MAGIC = [208, 207, 17, 224, 161, 177, 26, 225];
var DANGEROUS_OLE_STREAMS = [
  "VBA",
  "Macros",
  "_VBA_PROJECT",
  "VBAProject",
  "ThisDocument",
  "Module",
  "powershell",
  "cmd.exe",
  "wscript",
  "cscript"
];
var MACRO_PATTERNS = [
  { pattern: "Auto_Open", severity: "high", desc: "Auto-executing macro (Auto_Open)" },
  { pattern: "AutoOpen", severity: "high", desc: "Auto-executing macro (AutoOpen)" },
  { pattern: "AutoExec", severity: "high", desc: "Auto-executing macro (AutoExec)" },
  { pattern: "Document_Open", severity: "high", desc: "Auto-executing macro (Document_Open)" },
  { pattern: "Workbook_Open", severity: "high", desc: "Auto-executing macro (Workbook_Open)" },
  { pattern: "Shell", severity: "high", desc: "Shell command execution in macro" },
  { pattern: "WScript.Shell", severity: "critical", desc: "Windows Script Host Shell access" },
  { pattern: "Scripting.FileSystemObject", severity: "critical", desc: "File system access in macro" },
  { pattern: "CreateObject", severity: "medium", desc: "COM object creation in macro" },
  { pattern: "PowerShell", severity: "critical", desc: "PowerShell invocation from macro" },
  { pattern: "cmd /c", severity: "critical", desc: "Command prompt invocation from macro" },
  { pattern: "ADODB.Stream", severity: "high", desc: "Binary stream manipulation in macro" },
  { pattern: "URLDownloadToFile", severity: "critical", desc: "Remote file download capability" }
];
function searchBytes(data, pattern) {
  const encoder = new TextEncoder();
  const patternBytes = encoder.encode(pattern);
  const patternLower = encoder.encode(pattern.toLowerCase());
  outer: for (let i = 0; i <= data.length - patternBytes.length; i++) {
    for (let j = 0; j < patternBytes.length; j++) {
      const byte = data[i + j];
      if (byte !== patternBytes[j] && byte !== patternLower[j]) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}
function analyzeMacros(data, fileName) {
  const threats = [];
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  const isOle = OLE_MAGIC.every((b, i) => data[i] === b);
  const isOoxml = [".docx", ".xlsx", ".pptx"].includes(ext);
  const isLegacyOffice = [".doc", ".xls", ".ppt"].includes(ext);
  if (!isOle && !isOoxml && !isLegacyOffice) {
    return { threats, hasMacros: false };
  }
  let hasMacros = false;
  for (const stream of DANGEROUS_OLE_STREAMS) {
    if (searchBytes(data, stream)) {
      hasMacros = true;
      threats.push({
        category: "macro_embedded",
        severity: "high",
        description: `Embedded macro stream detected: "${stream}"`,
        location: fileName
      });
      break;
    }
  }
  for (const { pattern, severity, desc } of MACRO_PATTERNS) {
    if (searchBytes(data, pattern)) {
      hasMacros = true;
      threats.push({
        category: "macro_embedded",
        severity,
        description: desc,
        location: fileName,
        signature: pattern
      });
    }
  }
  if (isOle && isLegacyOffice && !hasMacros) {
    threats.push({
      category: "macro_embedded",
      severity: "low",
      description: "Legacy Office format (OLE2) \u2014 may contain macros that could not be fully parsed client-side.",
      location: fileName
    });
  }
  return { threats, hasMacros };
}

// src/scanner/analyzers/script-detector.ts
var PDF_THREATS = [
  { pattern: "/JavaScript", severity: "critical", desc: "JavaScript embedded in PDF" },
  { pattern: "/JS", severity: "high", desc: "JavaScript action in PDF" },
  { pattern: "/Launch", severity: "critical", desc: "Launch action in PDF \u2014 can execute programs" },
  { pattern: "/OpenAction", severity: "high", desc: "Auto-executing action on PDF open" },
  { pattern: "/AA", severity: "medium", desc: "Additional actions trigger in PDF" },
  { pattern: "/EmbeddedFile", severity: "medium", desc: "Embedded file inside PDF" },
  { pattern: "/RichMedia", severity: "medium", desc: "Rich media (Flash/video) embedded in PDF" },
  { pattern: "/XFA", severity: "high", desc: "XFA form data \u2014 can contain scripts" },
  { pattern: "/SubmitForm", severity: "medium", desc: "Form data auto-submission action" },
  { pattern: "/URI", severity: "low", desc: "External URI reference in PDF" }
];
var SVG_THREATS = [
  { pattern: "<script", severity: "critical", desc: "Script tag in SVG \u2014 enables XSS" },
  { pattern: "onload=", severity: "critical", desc: "Event handler in SVG \u2014 enables XSS" },
  { pattern: "onclick=", severity: "critical", desc: "Event handler in SVG \u2014 enables XSS" },
  { pattern: "onerror=", severity: "critical", desc: "Event handler in SVG \u2014 enables XSS" },
  { pattern: "javascript:", severity: "critical", desc: "JavaScript protocol in SVG" },
  { pattern: 'xlink:href="data:', severity: "high", desc: "Data URI in SVG \u2014 may embed payloads" },
  { pattern: "<foreignObject", severity: "high", desc: "foreignObject in SVG \u2014 can embed HTML/scripts" },
  { pattern: "<iframe", severity: "critical", desc: "iframe embedded in SVG" }
];
var HTML_THREATS = [
  { pattern: "<script", severity: "critical", desc: "Script tag found \u2014 possible HTML masquerading" },
  { pattern: "javascript:", severity: "critical", desc: "JavaScript protocol URI detected" },
  { pattern: "onerror=", severity: "high", desc: "Error event handler \u2014 potential XSS vector" },
  { pattern: "onload=", severity: "high", desc: "Load event handler \u2014 potential XSS vector" },
  { pattern: "eval(", severity: "critical", desc: "eval() call detected \u2014 code execution" }
];
function textSearch(data, pattern) {
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const text = decoder.decode(data);
  return text.toLowerCase().includes(pattern.toLowerCase());
}
function analyzeScripts(data, fileName, detectedMime) {
  const threats = [];
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  let hasScripts = false;
  if (ext === ".pdf" || detectedMime === "application/pdf") {
    for (const { pattern, severity, desc } of PDF_THREATS) {
      if (textSearch(data, pattern)) {
        hasScripts = true;
        threats.push({
          category: "script_injection",
          severity,
          description: desc,
          location: fileName,
          signature: pattern
        });
      }
    }
  }
  if (ext === ".svg" || detectedMime === "image/svg+xml") {
    for (const { pattern, severity, desc } of SVG_THREATS) {
      if (textSearch(data, pattern)) {
        hasScripts = true;
        threats.push({
          category: "script_injection",
          severity,
          description: desc,
          location: fileName,
          signature: pattern
        });
      }
    }
  }
  if (detectedMime === "application/octet-stream" || ext === ".txt" || ext === ".csv" || ext === ".rtf") {
    for (const { pattern, severity, desc } of HTML_THREATS) {
      if (textSearch(data, pattern)) {
        hasScripts = true;
        threats.push({
          category: "hidden_content",
          severity,
          description: `${desc} (found in ${ext} file \u2014 possible HTML smuggling)`,
          location: fileName,
          signature: pattern
        });
      }
    }
  }
  return { threats, hasScripts };
}

// src/scanner/analyzers/polyglot.ts
var SECONDARY_SIGNATURES = [
  { bytes: [77, 90], name: "PE executable" },
  { bytes: [127, 69, 76, 70], name: "ELF binary" },
  { bytes: [80, 75, 3, 4], name: "ZIP archive" },
  { bytes: [37, 80, 68, 70], name: "PDF document" },
  { bytes: [82, 97, 114, 33], name: "RAR archive" }
];
function findSignatureAt(data, offset) {
  for (const sig of SECONDARY_SIGNATURES) {
    if (offset + sig.bytes.length > data.length) continue;
    const match = sig.bytes.every((b, i) => data[offset + i] === b);
    if (match) return sig.name;
  }
  return null;
}
function analyzePolyglot(data, fileName, primaryMime) {
  const threats = [];
  let isPolyglot = false;
  const scanOffsets = [
    512,
    1024,
    4096,
    Math.floor(data.length / 2),
    data.length > 1024 ? data.length - 1024 : -1
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
          signature: found
        });
      }
    }
  }
  return { threats, isPolyglot };
}

// src/scanner/analyzers/structure.ts
var ZIP_BOMB_RATIO_THRESHOLD = 100;
var MAX_NESTED_DEPTH_WARNING = 3;
function countZipEntries(data) {
  let count = 0;
  const localHeader = [80, 75, 3, 4];
  for (let i = 0; i <= data.length - 4; i++) {
    if (data[i] === localHeader[0] && data[i + 1] === localHeader[1] && data[i + 2] === localHeader[2] && data[i + 3] === localHeader[3]) {
      count++;
    }
  }
  return count;
}
function readUint32LE(data, offset) {
  return (data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16 | data[offset + 3] << 24) >>> 0;
}
function estimateUncompressedSize(data) {
  let totalUncompressed = 0;
  const localHeader = [80, 75, 3, 4];
  for (let i = 0; i <= data.length - 30; i++) {
    if (data[i] === localHeader[0] && data[i + 1] === localHeader[1] && data[i + 2] === localHeader[2] && data[i + 3] === localHeader[3]) {
      totalUncompressed += readUint32LE(data, i + 22);
    }
  }
  return totalUncompressed;
}
function analyzeStructure(data, fileName, detectedMime) {
  const threats = [];
  let structureValid = true;
  let hasEmbeddedFiles = false;
  const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  const isZip = detectedMime === "application/zip" || [".zip", ".docx", ".xlsx", ".pptx"].includes(ext);
  if (isZip && data.length >= 4) {
    const entryCount = countZipEntries(data);
    hasEmbeddedFiles = entryCount > 1;
    if (entryCount > 1e4) {
      threats.push({
        category: "zip_bomb",
        severity: "critical",
        description: `Archive contains ${entryCount.toLocaleString()} entries \u2014 likely a zip bomb (file count decompression attack).`
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
          description: `Compression ratio ${ratio.toFixed(0)}:1 exceeds safe threshold \u2014 possible zip bomb.`
        });
        structureValid = false;
      }
    }
    if (entryCount > MAX_NESTED_DEPTH_WARNING * 100) {
      threats.push({
        category: "zip_bomb",
        severity: "high",
        description: `Unusually high number of nested entries (${entryCount}) \u2014 may be a decompression attack.`
      });
    }
  }
  if (data.length === 0) {
    threats.push({
      category: "suspicious_metadata",
      severity: "low",
      description: "File is empty (0 bytes)."
    });
    structureValid = false;
  }
  return { threats, structureValid, hasEmbeddedFiles };
}

// src/scanner/engine.ts
async function computeSha256(data) {
  const bytes = new Uint8Array(data);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function generateId() {
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}
function computeRiskScore(threats) {
  const weights = {
    critical: 40,
    high: 25,
    medium: 12,
    low: 5,
    info: 1
  };
  let score = 0;
  for (const t of threats) {
    score += weights[t.severity] ?? 0;
  }
  return Math.min(score, 100);
}
function deriveVerdict(riskScore, threats) {
  const hasCritical = threats.some((t) => t.severity === "critical");
  if (hasCritical || riskScore >= 70) return "malicious";
  if (riskScore >= 30) return "suspicious";
  return "clean";
}
async function scanFile(file, maxSizeMB = 100) {
  const startTime = performance.now();
  const id = generateId();
  const allThreats = [];
  if (file.size > maxSizeMB * 1024 * 1024) {
    allThreats.push({
      category: "oversized_file",
      severity: "medium",
      description: `File size (${(file.size / 1024 / 1024).toFixed(1)} MB) exceeds ${maxSizeMB} MB limit.`
    });
  }
  const buffer = await file.arrayBuffer();
  const data = new Uint8Array(buffer);
  const sha256 = await computeSha256(buffer);
  const header = data.slice(0, 64);
  const { detectedMime, threats: typeThreats, hasExecutable } = analyzeFileType(
    header,
    file.type,
    file.name
  );
  allThreats.push(...typeThreats);
  const { entropy, threats: entropyThreats } = analyzeEntropy(data, file.name);
  allThreats.push(...entropyThreats);
  const { threats: macroThreats, hasMacros } = analyzeMacros(data, file.name);
  allThreats.push(...macroThreats);
  const { threats: scriptThreats, hasScripts } = analyzeScripts(
    data,
    file.name,
    detectedMime
  );
  allThreats.push(...scriptThreats);
  const { threats: polyglotThreats } = analyzePolyglot(
    data,
    file.name,
    detectedMime
  );
  allThreats.push(...polyglotThreats);
  const { threats: structureThreats, structureValid, hasEmbeddedFiles } = analyzeStructure(data, file.name, detectedMime);
  allThreats.push(...structureThreats);
  const riskScore = computeRiskScore(allThreats);
  const verdict = deriveVerdict(riskScore, allThreats);
  const endTime = performance.now();
  const metadata = {
    declaredMimeType: file.type || "unknown",
    detectedMimeType: detectedMime,
    magicBytes: getMagicBytesHex(header),
    extension: file.name.slice(file.name.lastIndexOf(".")).toLowerCase(),
    sha256,
    entropy,
    hasEmbeddedFiles,
    hasExecutableContent: hasExecutable || hasScripts || hasMacros,
    structureValid
  };
  return {
    id,
    fileName: file.name,
    fileSize: file.size,
    scanStartedAt: new Date(Date.now() - (endTime - startTime)).toISOString(),
    scanCompletedAt: (/* @__PURE__ */ new Date()).toISOString(),
    scanDurationMs: Math.round(endTime - startTime),
    threats: allThreats,
    riskScore,
    verdict,
    metadata,
    quarantine: {
      status: verdict === "clean" ? "released" : "held",
      reason: verdict !== "clean" ? `Risk score ${riskScore}/100 \u2014 ${verdict}` : null
    },
    engineVersion: ENGINE_VERSION
  };
}

// src/scanner/quarantine.ts
var Quarantine = class {
  constructor() {
    this.held = /* @__PURE__ */ new Map();
  }
  add(file, report) {
    this.held.set(report.id, {
      file,
      report,
      quarantinedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  release(scanId) {
    const entry = this.held.get(scanId);
    if (!entry) return null;
    entry.report.quarantine.status = "released";
    entry.report.quarantine.reason = "Manually released from quarantine";
    this.held.delete(scanId);
    return entry.file;
  }
  destroy(scanId) {
    const entry = this.held.get(scanId);
    if (!entry) return false;
    entry.report.quarantine.status = "destroyed";
    entry.report.quarantine.reason = "File permanently discarded";
    this.held.delete(scanId);
    return true;
  }
  get(scanId) {
    return this.held.get(scanId);
  }
  getAll() {
    return Array.from(this.held.values());
  }
  getReport(scanId) {
    return this.held.get(scanId)?.report;
  }
  clear() {
    for (const entry of this.held.values()) {
      entry.report.quarantine.status = "destroyed";
    }
    this.held.clear();
  }
  get size() {
    return this.held.size;
  }
  shouldQuarantine(verdict, riskThreshold) {
    if (verdict === "malicious") return true;
    if (verdict === "suspicious") return true;
    return false;
  }
};

// src/api/client.ts
function generateSessionId() {
  return `sess_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}
function deriveOverallVerdict(reports) {
  if (reports.some((r) => r.verdict === "malicious")) return "malicious";
  if (reports.some((r) => r.verdict === "suspicious")) return "suspicious";
  return "clean";
}
function buildPayload(reports, clientId) {
  return {
    reports,
    clientId,
    sessionId: generateSessionId(),
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    totalFiles: reports.length,
    totalThreats: reports.reduce((sum, r) => sum + r.threats.length, 0),
    overallVerdict: deriveOverallVerdict(reports)
  };
}
async function submitScanReport(endpoint, reports, clientId) {
  const payload = buildPayload(reports, clientId);
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Sentinel-Version": reports[0]?.engineVersion ?? "unknown",
      "X-Sentinel-Client": clientId
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(
      `Sentinel API error: ${response.status} ${response.statusText}`
    );
  }
  return response.json();
}

// src/hooks/useFileScanner.ts
function useFileScanner(config = {}) {
  const {
    apiEndpoint,
    clientId = "default",
    maxFileSizeMB = 100,
    allowedExtensions,
    blockedExtensions,
    autoQuarantine = true,
    onScanComplete,
    onThreatDetected,
    onApiResponse
  } = config;
  const [reports, setReports] = react.useState([]);
  const [scanning, setScanning] = react.useState(false);
  const [progress, setProgress] = react.useState(null);
  const [error, setError] = react.useState(null);
  const [apiResponse, setApiResponse] = react.useState(null);
  const [approvedFiles, setApprovedFiles] = react.useState([]);
  const quarantineRef = react.useRef(new Quarantine());
  const [quarantineVersion, setQuarantineVersion] = react.useState(0);
  const validateExtension = react.useCallback(
    (fileName) => {
      const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
      if (blockedExtensions?.length) {
        if (blockedExtensions.includes(ext)) return false;
      }
      if (allowedExtensions?.length) {
        return allowedExtensions.includes(ext);
      }
      return true;
    },
    [allowedExtensions, blockedExtensions]
  );
  const scanFiles = react.useCallback(
    async (input) => {
      const files = Array.from(input);
      if (files.length === 0) return [];
      setScanning(true);
      setError(null);
      setApiResponse(null);
      setApprovedFiles([]);
      const results = [];
      try {
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          if (!validateExtension(file.name)) {
            const ext = file.name.slice(file.name.lastIndexOf("."));
            setError(`File type ${ext} is not allowed`);
            continue;
          }
          setProgress({
            phase: "analyzing",
            fileName: file.name,
            percentComplete: Math.round((i + 0.5) / files.length * 100)
          });
          const report = await scanFile(file, maxFileSizeMB);
          results.push(report);
          onScanComplete?.(report);
          for (const threat of report.threats) {
            onThreatDetected?.(threat, file);
          }
          if (autoQuarantine && report.verdict !== "clean") {
            quarantineRef.current.add(file, report);
            setQuarantineVersion((v) => v + 1);
          } else if (report.verdict === "clean") {
            setApprovedFiles((prev) => [...prev, file]);
          }
        }
        setReports(results);
        if (apiEndpoint && results.length > 0) {
          setProgress({
            phase: "reporting",
            fileName: "",
            percentComplete: 95
          });
          try {
            const response = await submitScanReport(
              apiEndpoint,
              results,
              clientId
            );
            setApiResponse(response);
            onApiResponse?.(response);
            if (response.fileDecisions) {
              for (const report of results) {
                const decision = response.fileDecisions[report.id];
                if (decision?.action === "approve") {
                  const released = quarantineRef.current.release(report.id);
                  if (released) {
                    setApprovedFiles((prev) => [...prev, released]);
                  }
                } else if (decision?.action === "reject") {
                  quarantineRef.current.destroy(report.id);
                }
              }
              setQuarantineVersion((v) => v + 1);
            }
          } catch (apiErr) {
            setError(
              `Scan completed but API submission failed: ${apiErr instanceof Error ? apiErr.message : "Unknown error"}`
            );
          }
        }
        setProgress({ phase: "reporting", fileName: "", percentComplete: 100 });
        return results;
      } catch (err) {
        const msg = err instanceof Error ? err.message : "An unexpected error occurred";
        setError(msg);
        return results;
      } finally {
        setScanning(false);
        setProgress(null);
      }
    },
    [
      apiEndpoint,
      clientId,
      maxFileSizeMB,
      autoQuarantine,
      validateExtension,
      onScanComplete,
      onThreatDetected,
      onApiResponse
    ]
  );
  const reset = react.useCallback(() => {
    setReports([]);
    setScanning(false);
    setProgress(null);
    setError(null);
    setApiResponse(null);
    setApprovedFiles([]);
    quarantineRef.current.clear();
    setQuarantineVersion((v) => v + 1);
  }, []);
  return {
    scanFiles,
    reports,
    scanning,
    progress,
    error,
    apiResponse,
    quarantine: {
      get held() {
        return quarantineRef.current.getAll().map((q) => q.report);
      },
      release: (scanId) => {
        const file = quarantineRef.current.release(scanId);
        if (file) {
          setApprovedFiles((prev) => [...prev, file]);
          setQuarantineVersion((v) => v + 1);
        }
        return file;
      },
      destroy: (scanId) => {
        const result = quarantineRef.current.destroy(scanId);
        if (result) setQuarantineVersion((v) => v + 1);
        return result;
      },
      clear: () => {
        quarantineRef.current.clear();
        setQuarantineVersion((v) => v + 1);
      }
    },
    approvedFiles,
    reset
  };
}
function FileScanner({
  children,
  onFilesApproved,
  accept,
  multiple = true,
  className,
  renderDefault = true,
  ...config
}) {
  const inputRef = react.useRef(null);
  const [dragOver, setDragOver] = react.useState(false);
  const {
    scanFiles,
    reports,
    scanning,
    progress,
    error,
    approvedFiles,
    quarantine,
    reset
  } = useFileScanner(config);
  const handleFiles = async (files) => {
    const results = await scanFiles(files);
    const cleanFiles = Array.from(files).filter(
      (_, i) => results[i]?.verdict === "clean"
    );
    if (cleanFiles.length > 0) {
      onFilesApproved?.(cleanFiles);
    }
  };
  const handleChange = (e) => {
    if (e.target.files?.length) {
      handleFiles(e.target.files);
      e.target.value = "";
    }
  };
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length) {
      handleFiles(e.dataTransfer.files);
    }
  };
  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };
  const handleDragLeave = () => setDragOver(false);
  const openFilePicker = () => inputRef.current?.click();
  const state = {
    scanning,
    reports,
    error,
    approvedFiles,
    quarantineCount: quarantine.held.length,
    openFilePicker,
    handleDrop,
    handleDragOver,
    reset
  };
  if (children) {
    return /* @__PURE__ */ jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [
      /* @__PURE__ */ jsxRuntime.jsx(
        "input",
        {
          ref: inputRef,
          type: "file",
          accept,
          multiple,
          onChange: handleChange,
          style: { display: "none" }
        }
      ),
      children(state)
    ] });
  }
  if (!renderDefault) return null;
  return /* @__PURE__ */ jsxRuntime.jsxs("div", { className, children: [
    /* @__PURE__ */ jsxRuntime.jsx(
      "input",
      {
        ref: inputRef,
        type: "file",
        accept,
        multiple,
        onChange: handleChange,
        style: { display: "none" }
      }
    ),
    /* @__PURE__ */ jsxRuntime.jsx(
      "div",
      {
        onClick: openFilePicker,
        onDrop: handleDrop,
        onDragOver: handleDragOver,
        onDragLeave: handleDragLeave,
        role: "button",
        tabIndex: 0,
        onKeyDown: (e) => {
          if (e.key === "Enter" || e.key === " ") openFilePicker();
        },
        style: {
          border: `2px dashed ${dragOver ? "#3b82f6" : "#d1d5db"}`,
          borderRadius: 12,
          padding: "2rem",
          textAlign: "center",
          cursor: "pointer",
          transition: "border-color 0.2s, background 0.2s",
          background: dragOver ? "rgba(59, 130, 246, 0.04)" : "transparent"
        },
        children: scanning ? /* @__PURE__ */ jsxRuntime.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntime.jsx("p", { style: { fontWeight: 600 }, children: "Scanning files..." }),
          progress && /* @__PURE__ */ jsxRuntime.jsxs("p", { style: { fontSize: 13, color: "#6b7280", marginTop: 4 }, children: [
            progress.phase === "analyzing" ? `Analyzing ${progress.fileName}` : "Submitting report...",
            " ",
            "\u2014 ",
            progress.percentComplete,
            "%"
          ] })
        ] }) : /* @__PURE__ */ jsxRuntime.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntime.jsx("p", { style: { fontWeight: 600 }, children: "Drop files here or click to browse" }),
          /* @__PURE__ */ jsxRuntime.jsx("p", { style: { fontSize: 13, color: "#6b7280", marginTop: 4 }, children: "Files are scanned for threats before upload" })
        ] })
      }
    ),
    error && /* @__PURE__ */ jsxRuntime.jsx("p", { style: { color: "#ef4444", fontSize: 13, marginTop: 8 }, children: error }),
    reports.length > 0 && /* @__PURE__ */ jsxRuntime.jsx("div", { style: { marginTop: 12 }, children: reports.map((r) => /* @__PURE__ */ jsxRuntime.jsxs(
      "div",
      {
        style: {
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "8px 12px",
          borderRadius: 8,
          marginBottom: 4,
          fontSize: 13,
          background: r.verdict === "clean" ? "rgba(34, 197, 94, 0.08)" : r.verdict === "suspicious" ? "rgba(234, 179, 8, 0.08)" : "rgba(239, 68, 68, 0.08)"
        },
        children: [
          /* @__PURE__ */ jsxRuntime.jsx("span", { children: r.fileName }),
          /* @__PURE__ */ jsxRuntime.jsxs(
            "span",
            {
              style: {
                fontWeight: 600,
                textTransform: "uppercase",
                fontSize: 11,
                color: r.verdict === "clean" ? "#16a34a" : r.verdict === "suspicious" ? "#ca8a04" : "#dc2626"
              },
              children: [
                r.verdict,
                " \u2014 risk ",
                r.riskScore,
                "/100"
              ]
            }
          )
        ]
      },
      r.id
    )) })
  ] });
}

exports.ENGINE_VERSION = ENGINE_VERSION;
exports.FileScanner = FileScanner;
exports.Quarantine = Quarantine;
exports.SUPPORTED_EXTENSIONS = SUPPORTED_EXTENSIONS;
exports.analyzeMacros = analyzeMacros;
exports.analyzePolyglot = analyzePolyglot;
exports.analyzeScripts = analyzeScripts;
exports.analyzeStructure = analyzeStructure;
exports.buildPayload = buildPayload;
exports.calculateEntropy = calculateEntropy;
exports.detectMimeType = detectMimeType;
exports.getMagicBytesHex = getMagicBytesHex;
exports.scanFile = scanFile;
exports.submitScanReport = submitScanReport;
exports.useFileScanner = useFileScanner;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map