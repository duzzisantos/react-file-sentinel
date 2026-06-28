# react-file-sentinel

**Client-side file threat scanner for React forms.**

Scans uploaded files for malware signatures, hidden macros, script injections, polyglot attacks, and suspicious payloads — before they ever reach your server. Quarantines threats in a sandboxed environment and sends structured scan reports to your backend API.

[![npm version](https://img.shields.io/npm/v/react-file-sentinel)](https://www.npmjs.com/package/react-file-sentinel)
[![license](https://img.shields.io/npm/l/react-file-sentinel)](LICENSE)
[![bundle size](https://img.shields.io/bundlephobia/minzip/react-file-sentinel)](https://bundlephobia.com/package/react-file-sentinel)

---

## Why This Exists

Every file upload is an attack surface. Most React apps validate file extensions and call it a day — but real threats are deeper:

- **A `.docx` with embedded VBA macros** that auto-executes PowerShell
- **A `.png` that's actually a PE executable** (polyglot file)
- **A `.pdf` with `<script>` injections** that trigger on open
- **An `.svg` with XSS payloads** via `onload` handlers
- **A `.zip` bomb** with a 100,000:1 compression ratio

**react-file-sentinel** catches these **client-side**, before the file touches your server. It's not a replacement for server-side scanning — it's your first line of defense.

---

## What It Detects

| Threat | Detection Method | Severity |
|--------|-----------------|----------|
| Executable binaries (.exe, .elf) | Magic byte signature matching | Critical |
| Polyglot files | Secondary signature scanning at multiple offsets | Critical |
| VBA macros in Office docs | OLE stream + pattern scanning | High-Critical |
| JavaScript in PDFs | PDF action keyword scanning | High-Critical |
| XSS in SVGs | Script tag + event handler detection | Critical |
| HTML smuggling in text files | Hidden `<script>` / `eval()` detection | High |
| Zip bombs | Entry count + compression ratio analysis | Critical |
| File type spoofing | Magic bytes vs declared MIME comparison | Medium-High |
| Encrypted/packed payloads | Shannon entropy analysis | Medium-High |
| Empty/malformed files | Structure validation | Low |

---

## Supported File Types

**Documents:** `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.ppt`, `.odt`, `.ods`, `.odp`, `.rtf`, `.txt`, `.csv`

**Images:** `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp`, `.svg`

**Archives:** `.zip`, `.tar`, `.gz`, `.7z`, `.rar`

**Media:** `.mp3`, `.mp4`, `.wav`, `.avi`, `.mov`

---

## Installation

```bash
npm install react-file-sentinel
```

```bash
yarn add react-file-sentinel
```

```bash
pnpm add react-file-sentinel
```

---

## Quick Start

### 1. Hook — Full Control

```tsx
import { useFileScanner } from "react-file-sentinel";

function UploadForm() {
  const { scanFiles, reports, scanning, approvedFiles, quarantine } =
    useFileScanner({
      apiEndpoint: "https://api.example.com/scan",
      clientId: "my-app",
      maxFileSizeMB: 50,
      onThreatDetected: (threat, file) => {
        console.warn(`Threat in ${file.name}:`, threat.description);
      },
    });

  const handleChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;
    const results = await scanFiles(e.target.files);

    results.forEach((r) => {
      if (r.verdict === "clean") {
        console.log(`${r.fileName} is safe to upload`);
      } else {
        console.log(`${r.fileName} quarantined: ${r.verdict} (risk: ${r.riskScore}/100)`);
      }
    });
  };

  return (
    <div>
      <input type="file" multiple onChange={handleChange} />

      {scanning && <p>Scanning files...</p>}

      {reports.map((r) => (
        <div key={r.id}>
          {r.fileName}: {r.verdict} ({r.threats.length} threats, risk {r.riskScore}/100)
        </div>
      ))}

      {quarantine.held.length > 0 && (
        <div>
          <h3>{quarantine.held.length} file(s) quarantined</h3>
          {quarantine.held.map((r) => (
            <div key={r.id}>
              {r.fileName}
              <button onClick={() => quarantine.release(r.id)}>Release</button>
              <button onClick={() => quarantine.destroy(r.id)}>Discard</button>
            </div>
          ))}
        </div>
      )}

      <p>{approvedFiles.length} file(s) ready to upload</p>
    </div>
  );
}
```

### 2. Drop-in Component

```tsx
import { FileScanner } from "react-file-sentinel";

function App() {
  return (
    <FileScanner
      apiEndpoint="https://api.example.com/scan"
      clientId="my-app"
      multiple
      onFilesApproved={(files) => {
        // Only fires for files that pass scanning
        const formData = new FormData();
        files.forEach((f) => formData.append("files", f));
        fetch("/upload", { method: "POST", body: formData });
      }}
    />
  );
}
```

### 3. Render Props — Custom UI

```tsx
import { FileScanner } from "react-file-sentinel";

function CustomUpload() {
  return (
    <FileScanner
      apiEndpoint="https://api.example.com/scan"
      clientId="my-app"
    >
      {({ scanning, reports, openFilePicker, handleDrop, handleDragOver }) => (
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onClick={openFilePicker}
          className="dropzone"
        >
          {scanning ? "Scanning..." : "Drop files here"}
          {reports.map((r) => (
            <span key={r.id} className={`badge-${r.verdict}`}>
              {r.fileName}: {r.verdict}
            </span>
          ))}
        </div>
      )}
    </FileScanner>
  );
}
```

---

## Usage with UI Libraries

### Shadcn/ui

```tsx
import { useFileScanner } from "react-file-sentinel";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

function ShadcnUpload() {
  const { scanFiles, reports, scanning, approvedFiles } = useFileScanner({
    apiEndpoint: "/api/scan",
    clientId: "shadcn-app",
  });

  return (
    <Card>
      <CardContent className="pt-6 space-y-4">
        <Input
          type="file"
          multiple
          onChange={(e) => e.target.files && scanFiles(e.target.files)}
          disabled={scanning}
        />

        {reports.map((r) => (
          <div key={r.id} className="flex items-center justify-between">
            <span className="text-sm">{r.fileName}</span>
            <Badge variant={r.verdict === "clean" ? "default" : "destructive"}>
              {r.verdict}
            </Badge>
          </div>
        ))}

        <Button disabled={approvedFiles.length === 0}>
          Upload {approvedFiles.length} file(s)
        </Button>
      </CardContent>
    </Card>
  );
}
```

### Bootstrap / Plain HTML

```tsx
import { useFileScanner } from "react-file-sentinel";

function BootstrapUpload() {
  const { scanFiles, reports, scanning } = useFileScanner({
    apiEndpoint: "/api/scan",
    clientId: "bootstrap-app",
  });

  return (
    <div className="card p-4">
      <div className="mb-3">
        <label className="form-label">Upload Files</label>
        <input
          className="form-control"
          type="file"
          multiple
          onChange={(e) => e.target.files && scanFiles(e.target.files)}
          disabled={scanning}
        />
      </div>

      {reports.map((r) => (
        <div key={r.id} className={`alert alert-${r.verdict === "clean" ? "success" : "danger"} py-2`}>
          <strong>{r.fileName}</strong> — {r.verdict} (risk: {r.riskScore}/100)
          <ul className="mb-0 mt-1">
            {r.threats.map((t, i) => (
              <li key={i}>{t.description}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
```

---

## API Payload Shape

When `apiEndpoint` is configured, the scanner sends this payload via `POST`:

```typescript
interface ScanAPIPayload {
  reports: ScanReport[];        // Full scan report per file
  clientId: string;             // Your app identifier
  sessionId: string;            // Auto-generated session ID
  timestamp: string;            // ISO 8601
  totalFiles: number;
  totalThreats: number;
  overallVerdict: "clean" | "suspicious" | "malicious";
}
```

Your backend should respond with:

```typescript
interface ScanAPIResponse {
  accepted: boolean;
  fileDecisions: Record<string, {
    action: "approve" | "reject" | "quarantine";
    reason?: string;
  }>;
  message: string;
}
```

Files keyed by `scanId`. The hook will automatically release approved files and destroy rejected ones.

---

## Configuration

```typescript
interface SentinelConfig {
  apiEndpoint?: string;          // Backend URL for scan reports
  clientId?: string;             // Your app identifier (default: "default")
  maxFileSizeMB?: number;        // Max file size in MB (default: 100)
  allowedExtensions?: string[];  // Whitelist: [".pdf", ".png", ".docx"]
  blockedExtensions?: string[];  // Blacklist: [".exe", ".bat", ".sh"]
  autoQuarantine?: boolean;      // Auto-quarantine threats (default: true)
  riskThreshold?: number;        // Risk score threshold (0-100)
  onScanComplete?: (report: ScanReport) => void;
  onThreatDetected?: (threat: Threat, file: File) => void;
  onApiResponse?: (response: ScanAPIResponse) => void;
}
```

---

## Scan Report Structure

Every scanned file produces a `ScanReport`:

```typescript
{
  id: "scan_1719500000_a1b2c3d4",
  fileName: "report.docx",
  fileSize: 245760,
  scanStartedAt: "2026-06-28T12:00:00.000Z",
  scanCompletedAt: "2026-06-28T12:00:00.045Z",
  scanDurationMs: 45,
  threats: [
    {
      category: "macro_embedded",
      severity: "high",
      description: "Embedded macro stream detected: \"VBAProject\"",
      location: "report.docx",
    }
  ],
  riskScore: 25,
  verdict: "suspicious",
  metadata: {
    declaredMimeType: "application/vnd.openxmlformats-officedocument...",
    detectedMimeType: "application/zip",
    magicBytes: "50 4b 03 04 14 00 06 00",
    extension: ".docx",
    sha256: "e3b0c44298fc1c149afbf4c8996fb924...",
    entropy: 7.2,
    hasEmbeddedFiles: true,
    hasExecutableContent: true,
    structureValid: true,
  },
  quarantine: {
    status: "held",
    reason: "Risk score 25/100 — suspicious"
  },
  engineVersion: "1.0.0"
}
```

---

## Advanced: Standalone Scanner

Use the scan engine directly without React:

```typescript
import { scanFile } from "react-file-sentinel";

const input = document.querySelector<HTMLInputElement>("#file-input")!;
input.addEventListener("change", async () => {
  for (const file of input.files!) {
    const report = await scanFile(file);
    console.log(report.verdict, report.threats);
  }
});
```

---

## Security Notes

- This is a **client-side heuristic scanner** — it's a first line of defense, not a complete antivirus solution
- Always pair with **server-side scanning** (ClamAV, VirusTotal API, etc.) for production systems
- The scanner runs entirely in the browser — no files are sent to third parties
- SHA-256 hashing uses the Web Crypto API (`crypto.subtle`)
- File contents are processed in memory and never persisted to disk

---

## License

[MIT](LICENSE)
# react-file-sentinel
