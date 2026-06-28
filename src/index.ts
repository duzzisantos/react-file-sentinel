export { useFileScanner } from "./hooks/useFileScanner";
export { FileScanner } from "./components/FileScanner";
export type { FileScannerState } from "./components/FileScanner";

export { scanFile } from "./scanner/engine";
export { Quarantine } from "./scanner/quarantine";
export { buildPayload, submitScanReport } from "./api/client";

export { calculateEntropy } from "./scanner/analyzers/entropy";
export { detectMimeType, getMagicBytesHex } from "./scanner/analyzers/magic-bytes";
export { analyzeMacros } from "./scanner/analyzers/macro-detector";
export { analyzeScripts } from "./scanner/analyzers/script-detector";
export { analyzePolyglot } from "./scanner/analyzers/polyglot";
export { analyzeStructure } from "./scanner/analyzers/structure";

export type {
  ThreatSeverity,
  ThreatCategory,
  ScanVerdict,
  QuarantineStatus,
  Threat,
  FileMetadata,
  ScanReport,
  ScanAPIPayload,
  ScanAPIResponse,
  SentinelConfig,
  ScanProgress,
} from "./types";

export { ENGINE_VERSION, SUPPORTED_EXTENSIONS } from "./types";
