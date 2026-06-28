import * as react from 'react';
import { DragEvent } from 'react';

type ThreatSeverity = "critical" | "high" | "medium" | "low" | "info";
type ThreatCategory = "malware_signature" | "macro_embedded" | "script_injection" | "polyglot_file" | "file_type_mismatch" | "entropy_anomaly" | "zip_bomb" | "hidden_content" | "suspicious_metadata" | "oversized_file";
type ScanVerdict = "clean" | "suspicious" | "malicious";
type QuarantineStatus = "held" | "released" | "destroyed";
interface Threat {
    category: ThreatCategory;
    severity: ThreatSeverity;
    description: string;
    location?: string;
    signature?: string;
}
interface FileMetadata {
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
interface ScanReport {
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
interface ScanAPIPayload {
    reports: ScanReport[];
    clientId: string;
    sessionId: string;
    timestamp: string;
    totalFiles: number;
    totalThreats: number;
    overallVerdict: ScanVerdict;
}
interface ScanAPIResponse {
    accepted: boolean;
    fileDecisions: Record<string, {
        action: "approve" | "reject" | "quarantine";
        reason?: string;
    }>;
    message: string;
}
interface SentinelConfig {
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
interface ScanProgress {
    phase: "reading" | "analyzing" | "reporting";
    fileName: string;
    percentComplete: number;
}
declare const ENGINE_VERSION = "1.0.0";
declare const SUPPORTED_EXTENSIONS: readonly [".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".zip", ".tar", ".gz", ".7z", ".rar", ".mp3", ".mp4", ".wav", ".avi", ".mov"];

interface UseFileScannerReturn {
    scanFiles: (files: FileList | File[]) => Promise<ScanReport[]>;
    reports: ScanReport[];
    scanning: boolean;
    progress: ScanProgress | null;
    error: string | null;
    apiResponse: ScanAPIResponse | null;
    quarantine: {
        held: ScanReport[];
        release: (scanId: string) => File | null;
        destroy: (scanId: string) => boolean;
        clear: () => void;
    };
    approvedFiles: File[];
    reset: () => void;
}
declare function useFileScanner(config?: SentinelConfig): UseFileScannerReturn;

interface FileScannerProps extends SentinelConfig {
    children?: (state: FileScannerState) => React.ReactNode;
    onFilesApproved?: (files: File[]) => void;
    accept?: string;
    multiple?: boolean;
    className?: string;
    renderDefault?: boolean;
}
interface FileScannerState {
    scanning: boolean;
    reports: ScanReport[];
    error: string | null;
    approvedFiles: File[];
    quarantineCount: number;
    openFilePicker: () => void;
    handleDrop: (e: DragEvent) => void;
    handleDragOver: (e: DragEvent) => void;
    reset: () => void;
}
declare function FileScanner({ children, onFilesApproved, accept, multiple, className, renderDefault, ...config }: FileScannerProps): react.JSX.Element | null;

declare function scanFile(file: File, maxSizeMB?: number): Promise<ScanReport>;

interface QuarantinedFile {
    file: File;
    report: ScanReport;
    quarantinedAt: string;
}
declare class Quarantine {
    private held;
    add(file: File, report: ScanReport): void;
    release(scanId: string): File | null;
    destroy(scanId: string): boolean;
    get(scanId: string): QuarantinedFile | undefined;
    getAll(): QuarantinedFile[];
    getReport(scanId: string): ScanReport | undefined;
    clear(): void;
    get size(): number;
    shouldQuarantine(verdict: ScanVerdict, riskThreshold: number): boolean;
}

declare function buildPayload(reports: ScanReport[], clientId: string): ScanAPIPayload;
declare function submitScanReport(endpoint: string, reports: ScanReport[], clientId: string): Promise<ScanAPIResponse>;

declare function calculateEntropy(data: Uint8Array): number;

declare function detectMimeType(header: Uint8Array): string;
declare function getMagicBytesHex(header: Uint8Array): string;

declare function analyzeMacros(data: Uint8Array, fileName: string): {
    threats: Threat[];
    hasMacros: boolean;
};

declare function analyzeScripts(data: Uint8Array, fileName: string, detectedMime: string): {
    threats: Threat[];
    hasScripts: boolean;
};

declare function analyzePolyglot(data: Uint8Array, fileName: string, primaryMime: string): {
    threats: Threat[];
    isPolyglot: boolean;
};

declare function analyzeStructure(data: Uint8Array, fileName: string, detectedMime: string): {
    threats: Threat[];
    structureValid: boolean;
    hasEmbeddedFiles: boolean;
};

export { ENGINE_VERSION, type FileMetadata, FileScanner, type FileScannerState, Quarantine, type QuarantineStatus, SUPPORTED_EXTENSIONS, type ScanAPIPayload, type ScanAPIResponse, type ScanProgress, type ScanReport, type ScanVerdict, type SentinelConfig, type Threat, type ThreatCategory, type ThreatSeverity, analyzeMacros, analyzePolyglot, analyzeScripts, analyzeStructure, buildPayload, calculateEntropy, detectMimeType, getMagicBytesHex, scanFile, submitScanReport, useFileScanner };
