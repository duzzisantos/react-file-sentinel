import { describe, it, expect } from "vitest";
import { scanFile } from "../src/scanner/engine";

function createMockFile(
  name: string,
  content: Uint8Array,
  type: string = "",
): File {
  const blob = new Blob([content], { type });
  const file = new File([blob], name, { type });
  if (!file.arrayBuffer) {
    file.arrayBuffer = () =>
      new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result as ArrayBuffer);
        reader.readAsArrayBuffer(blob);
      });
  }
  return file;
}

describe("scanFile", () => {
  it("scans a clean PNG file", async () => {
    const header = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const body = new Uint8Array(1000).fill(0x42);
    const content = new Uint8Array([...header, ...body]);

    const file = createMockFile("photo.png", content, "image/png");
    const report = await scanFile(file);

    expect(report.fileName).toBe("photo.png");
    expect(report.verdict).toBe("clean");
    expect(report.riskScore).toBeLessThan(30);
    expect(report.metadata.detectedMimeType).toBe("image/png");
    expect(report.metadata.sha256).toHaveLength(64);
    expect(report.quarantine.status).toBe("released");
    expect(report.scanDurationMs).toBeGreaterThanOrEqual(0);
    expect(report.id).toMatch(/^scan_/);
  });

  it("flags an executable as malicious", async () => {
    const content = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...new Array(100).fill(0)]);
    const file = createMockFile("payload.exe", content, "application/x-msdownload");
    const report = await scanFile(file);

    expect(report.verdict).toBe("malicious");
    expect(report.riskScore).toBeGreaterThanOrEqual(40);
    expect(report.metadata.hasExecutableContent).toBe(true);
    expect(report.quarantine.status).toBe("held");
  });

  it("detects a PDF with JavaScript", async () => {
    const text = new TextEncoder().encode("%PDF-1.4 /JavaScript (alert(1)) /OpenAction");
    const file = createMockFile("doc.pdf", text, "application/pdf");
    const report = await scanFile(file);

    expect(report.verdict).toBe("malicious");
    expect(report.threats.some((t) => t.category === "script_injection")).toBe(true);
    expect(report.metadata.hasExecutableContent).toBe(true);
  });

  it("detects an oversized file", async () => {
    const content = new Uint8Array(100);
    const file = createMockFile("huge.bin", content, "application/octet-stream");
    Object.defineProperty(file, "size", { value: 200 * 1024 * 1024 });

    const report = await scanFile(file, 100);
    expect(report.threats.some((t) => t.category === "oversized_file")).toBe(true);
  });

  it("returns complete metadata structure", async () => {
    const content = new Uint8Array([0x89, 0x50, 0x4e, 0x47, ...new Array(100).fill(0)]);
    const file = createMockFile("test.png", content, "image/png");
    const report = await scanFile(file);

    expect(report.metadata).toHaveProperty("declaredMimeType");
    expect(report.metadata).toHaveProperty("detectedMimeType");
    expect(report.metadata).toHaveProperty("magicBytes");
    expect(report.metadata).toHaveProperty("extension");
    expect(report.metadata).toHaveProperty("sha256");
    expect(report.metadata).toHaveProperty("entropy");
    expect(report.metadata).toHaveProperty("hasEmbeddedFiles");
    expect(report.metadata).toHaveProperty("hasExecutableContent");
    expect(report.metadata).toHaveProperty("structureValid");
    expect(report.metadata.extension).toBe(".png");
  });
});
