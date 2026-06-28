import { useRef, type ChangeEvent, type DragEvent, useState } from "react";
import { useFileScanner } from "../hooks/useFileScanner";
import type { SentinelConfig, ScanReport } from "../types";

interface FileScannerProps extends SentinelConfig {
  children?: (state: FileScannerState) => React.ReactNode;
  onFilesApproved?: (files: File[]) => void;
  accept?: string;
  multiple?: boolean;
  className?: string;
  renderDefault?: boolean;
}

export interface FileScannerState {
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

export function FileScanner({
  children,
  onFilesApproved,
  accept,
  multiple = true,
  className,
  renderDefault = true,
  ...config
}: FileScannerProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  const {
    scanFiles,
    reports,
    scanning,
    progress,
    error,
    approvedFiles,
    quarantine,
    reset,
  } = useFileScanner(config);

  const handleFiles = async (files: FileList | File[]) => {
    const results = await scanFiles(files);
    const cleanFiles = Array.from(files).filter((_, i) =>
      results[i]?.verdict === "clean",
    );
    if (cleanFiles.length > 0) {
      onFilesApproved?.(cleanFiles);
    }
  };

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      handleFiles(e.target.files);
      e.target.value = "";
    }
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length) {
      handleFiles(e.dataTransfer.files);
    }
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => setDragOver(false);

  const openFilePicker = () => inputRef.current?.click();

  const state: FileScannerState = {
    scanning,
    reports,
    error,
    approvedFiles,
    quarantineCount: quarantine.held.length,
    openFilePicker,
    handleDrop,
    handleDragOver,
    reset,
  };

  if (children) {
    return (
      <>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={multiple}
          onChange={handleChange}
          style={{ display: "none" }}
        />
        {children(state)}
      </>
    );
  }

  if (!renderDefault) return null;

  return (
    <div className={className}>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        multiple={multiple}
        onChange={handleChange}
        style={{ display: "none" }}
      />
      <div
        onClick={openFilePicker}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") openFilePicker();
        }}
        style={{
          border: `2px dashed ${dragOver ? "#3b82f6" : "#d1d5db"}`,
          borderRadius: 12,
          padding: "2rem",
          textAlign: "center",
          cursor: "pointer",
          transition: "border-color 0.2s, background 0.2s",
          background: dragOver ? "rgba(59, 130, 246, 0.04)" : "transparent",
        }}
      >
        {scanning ? (
          <div>
            <p style={{ fontWeight: 600 }}>Scanning files...</p>
            {progress && (
              <p style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>
                {progress.phase === "analyzing"
                  ? `Analyzing ${progress.fileName}`
                  : "Submitting report..."}
                {" "}— {progress.percentComplete}%
              </p>
            )}
          </div>
        ) : (
          <div>
            <p style={{ fontWeight: 600 }}>
              Drop files here or click to browse
            </p>
            <p style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>
              Files are scanned for threats before upload
            </p>
          </div>
        )}
      </div>

      {error && (
        <p style={{ color: "#ef4444", fontSize: 13, marginTop: 8 }}>{error}</p>
      )}

      {reports.length > 0 && (
        <div style={{ marginTop: 12 }}>
          {reports.map((r) => (
            <div
              key={r.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "8px 12px",
                borderRadius: 8,
                marginBottom: 4,
                fontSize: 13,
                background:
                  r.verdict === "clean"
                    ? "rgba(34, 197, 94, 0.08)"
                    : r.verdict === "suspicious"
                      ? "rgba(234, 179, 8, 0.08)"
                      : "rgba(239, 68, 68, 0.08)",
              }}
            >
              <span>{r.fileName}</span>
              <span
                style={{
                  fontWeight: 600,
                  textTransform: "uppercase",
                  fontSize: 11,
                  color:
                    r.verdict === "clean"
                      ? "#16a34a"
                      : r.verdict === "suspicious"
                        ? "#ca8a04"
                        : "#dc2626",
                }}
              >
                {r.verdict} — risk {r.riskScore}/100
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
