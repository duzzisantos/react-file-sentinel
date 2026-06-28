export type ThreatSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ThreatCategory =
  | "malware_signature"
  | "macro_embedded"
  | "script_injection"
  | "polyglot_file"
  | "file_type_mismatch"
  | "entropy_anomaly"
  | "zip_bomb"
  | "hidden_content"
  | "suspicious_metadata"
  | "oversized_file";

export type ScanVerdict = "clean" | "suspicious" | "malicious";

export type QuarantineStatus = "held" | "released" | "destroyed";

export interface Threat {
  category: ThreatCategory;
  severity: ThreatSeverity;
  description: string;
  location?: string;
  signature?: string;
}

export interface FileMetadata {
  declaredMimeType: string;
  detectedMimeType: string;
  magicBytes: string;
  extension: string;
  sha256: string;
  entropy: number;
  hasEmbeddedFiles: boolean;
  hasExecutableContent: boolean;
  structureValid: boolean;
}

export interface ScanReport {
  id: string;
  fileName: string;
  fileSize: number;
  scanStartedAt: string;
  scanCompletedAt: string;
  scanDurationMs: number;
  threats: Threat[];
  riskScore: number;
  verdict: ScanVerdict;
  metadata: FileMetadata;
  quarantine: {
    status: QuarantineStatus;
    reason: string | null;
  };
  engineVersion: string;
}

export interface ScanAPIPayload {
  reports: ScanReport[];
  clientId: string;
  sessionId: string;
  timestamp: string;
  totalFiles: number;
  totalThreats: number;
  overallVerdict: ScanVerdict;
}

export interface ScanAPIResponse {
  accepted: boolean;
  fileDecisions: Record<
    string,
    {
      action: "approve" | "reject" | "quarantine";
      reason?: string;
    }
  >;
  message: string;
}

export interface SentinelConfig {
  apiEndpoint?: string;
  clientId?: string;
  maxFileSizeMB?: number;
  allowedExtensions?: string[];
  blockedExtensions?: string[];
  autoQuarantine?: boolean;
  riskThreshold?: number;
  onScanComplete?: (report: ScanReport) => void;
  onThreatDetected?: (threat: Threat, file: File) => void;
  onApiResponse?: (response: ScanAPIResponse) => void;
}

export interface ScanProgress {
  phase: "reading" | "analyzing" | "reporting";
  fileName: string;
  percentComplete: number;
}

export const ENGINE_VERSION = "1.0.0";

export const SUPPORTED_EXTENSIONS = [
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
  ".mov",
] as const;
