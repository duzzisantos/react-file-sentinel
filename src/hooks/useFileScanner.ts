import { useState, useCallback, useRef } from "react";
import type {
  ScanReport,
  ScanAPIResponse,
  SentinelConfig,
  ScanProgress,
} from "../types";
import { scanFile } from "../scanner/engine";
import { Quarantine } from "../scanner/quarantine";
import { submitScanReport } from "../api/client";

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

export function useFileScanner(
  config: SentinelConfig = {},
): UseFileScannerReturn {
  const {
    apiEndpoint,
    clientId = "default",
    maxFileSizeMB = 100,
    allowedExtensions,
    blockedExtensions,
    autoQuarantine = true,
    onScanComplete,
    onThreatDetected,
    onApiResponse,
  } = config;

  const [reports, setReports] = useState<ScanReport[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [apiResponse, setApiResponse] = useState<ScanAPIResponse | null>(null);
  const [approvedFiles, setApprovedFiles] = useState<File[]>([]);

  const quarantineRef = useRef(new Quarantine());
  const [quarantineVersion, setQuarantineVersion] = useState(0);

  const validateExtension = useCallback(
    (fileName: string): boolean => {
      const ext = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();

      if (blockedExtensions?.length) {
        if (blockedExtensions.includes(ext)) return false;
      }

      if (allowedExtensions?.length) {
        return allowedExtensions.includes(ext);
      }

      return true;
    },
    [allowedExtensions, blockedExtensions],
  );

  const scanFiles = useCallback(
    async (input: FileList | File[]): Promise<ScanReport[]> => {
      const files = Array.from(input);
      if (files.length === 0) return [];

      setScanning(true);
      setError(null);
      setApiResponse(null);
      setApprovedFiles([]);

      const results: ScanReport[] = [];

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
            percentComplete: Math.round(((i + 0.5) / files.length) * 100),
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
            percentComplete: 95,
          });

          try {
            const response = await submitScanReport(
              apiEndpoint,
              results,
              clientId,
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
              `Scan completed but API submission failed: ${apiErr instanceof Error ? apiErr.message : "Unknown error"}`,
            );
          }
        }

        setProgress({ phase: "reporting", fileName: "", percentComplete: 100 });
        return results;
      } catch (err) {
        const msg =
          err instanceof Error ? err.message : "An unexpected error occurred";
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
      onApiResponse,
    ],
  );

  const reset = useCallback(() => {
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
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        quarantineVersion;
        return quarantineRef.current.getAll().map((q) => q.report);
      },
      release: (scanId: string) => {
        const file = quarantineRef.current.release(scanId);
        if (file) {
          setApprovedFiles((prev) => [...prev, file]);
          setQuarantineVersion((v) => v + 1);
        }
        return file;
      },
      destroy: (scanId: string) => {
        const result = quarantineRef.current.destroy(scanId);
        if (result) setQuarantineVersion((v) => v + 1);
        return result;
      },
      clear: () => {
        quarantineRef.current.clear();
        setQuarantineVersion((v) => v + 1);
      },
    },
    approvedFiles,
    reset,
  };
}
