import { describe, it, expect } from "vitest";
import { detectMimeType, getMagicBytesHex, analyzeFileType } from "../src/scanner/analyzers/magic-bytes";
import { calculateEntropy, analyzeEntropy } from "../src/scanner/analyzers/entropy";
import { analyzeMacros } from "../src/scanner/analyzers/macro-detector";
import { analyzeScripts } from "../src/scanner/analyzers/script-detector";
import { analyzePolyglot } from "../src/scanner/analyzers/polyglot";
import { analyzeStructure } from "../src/scanner/analyzers/structure";

describe("magic-bytes", () => {
  it("detects PNG files", () => {
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(detectMimeType(png)).toBe("image/png");
  });

  it("detects PDF files", () => {
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e]);
    expect(detectMimeType(pdf)).toBe("application/pdf");
  });

  it("detects JPEG files", () => {
    const jpg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);
    expect(detectMimeType(jpg)).toBe("image/jpeg");
  });

  it("detects ZIP files", () => {
    const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
    expect(detectMimeType(zip)).toBe("application/zip");
  });

  it("detects PE executables", () => {
    const exe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    expect(detectMimeType(exe)).toBe("application/x-msdownload");
  });

  it("returns octet-stream for unknown files", () => {
    const unknown = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    expect(detectMimeType(unknown)).toBe("application/octet-stream");
  });

  it("formats magic bytes as hex string", () => {
    const data = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(getMagicBytesHex(data)).toBe("89 50 4e 47 0d 0a 1a 0a");
  });

  it("flags executable disguised as image", () => {
    const exe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...new Array(60).fill(0)]);
    const result = analyzeFileType(exe, "image/png", "photo.png");
    expect(result.hasExecutable).toBe(true);
    expect(result.threats.length).toBeGreaterThan(0);
    expect(result.threats[0].severity).toBe("critical");
  });

  it("treats OOXML as valid zip-based format", () => {
    const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(60).fill(0)]);
    const result = analyzeFileType(
      zip,
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "report.docx",
    );
    expect(result.threats).toHaveLength(0);
  });
});

describe("entropy", () => {
  it("returns 0 for empty data", () => {
    expect(calculateEntropy(new Uint8Array([]))).toBe(0);
  });

  it("returns 0 for uniform data", () => {
    const uniform = new Uint8Array(1000).fill(0x41);
    expect(calculateEntropy(uniform)).toBe(0);
  });

  it("returns high entropy for random data", () => {
    const random = new Uint8Array(10000);
    for (let i = 0; i < random.length; i++) {
      random[i] = Math.floor(Math.random() * 256);
    }
    expect(calculateEntropy(random)).toBeGreaterThan(7.0);
  });

  it("flags extremely high entropy as suspicious", () => {
    const random = new Uint8Array(10000);
    for (let i = 0; i < random.length; i++) {
      random[i] = Math.floor(Math.random() * 256);
    }
    const { threats } = analyzeEntropy(random, "data.txt");
    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0].category).toBe("entropy_anomaly");
  });

  it("does not flag compressed files for high entropy", () => {
    const random = new Uint8Array(10000);
    for (let i = 0; i < random.length; i++) {
      random[i] = Math.floor(Math.random() * 256);
    }
    const { threats } = analyzeEntropy(random, "archive.zip");
    expect(threats).toHaveLength(0);
  });
});

describe("macro-detector", () => {
  it("returns no threats for non-Office files", () => {
    const data = new Uint8Array(100);
    const { threats, hasMacros } = analyzeMacros(data, "image.png");
    expect(threats).toHaveLength(0);
    expect(hasMacros).toBe(false);
  });

  it("detects VBA project in docx", () => {
    const text = new TextEncoder().encode("some data VBAProject more data");
    const { threats, hasMacros } = analyzeMacros(text, "report.docx");
    expect(hasMacros).toBe(true);
    expect(threats.some((t) => t.category === "macro_embedded")).toBe(true);
  });

  it("detects Auto_Open macro pattern", () => {
    const text = new TextEncoder().encode("Sub Auto_Open()");
    const data = new Uint8Array([
      0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
      ...text,
    ]);
    const { threats } = analyzeMacros(data, "malicious.doc");
    expect(threats.some((t) => t.description.includes("Auto_Open"))).toBe(true);
  });

  it("detects PowerShell execution", () => {
    const text = new TextEncoder().encode("Shell PowerShell.exe -Command");
    const data = new Uint8Array([
      0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
      ...text,
    ]);
    const { threats } = analyzeMacros(data, "payload.xls");
    expect(threats.some((t) => t.severity === "critical")).toBe(true);
  });
});

describe("script-detector", () => {
  it("detects JavaScript in PDF", () => {
    const text = new TextEncoder().encode("%PDF-1.4 /JavaScript (alert)");
    const { threats, hasScripts } = analyzeScripts(text, "doc.pdf", "application/pdf");
    expect(hasScripts).toBe(true);
    expect(threats[0].category).toBe("script_injection");
  });

  it("detects script tags in SVG", () => {
    const text = new TextEncoder().encode('<svg><script>alert(1)</script></svg>');
    const { threats, hasScripts } = analyzeScripts(text, "icon.svg", "image/svg+xml");
    expect(hasScripts).toBe(true);
    expect(threats[0].severity).toBe("critical");
  });

  it("detects HTML smuggling in text files", () => {
    const text = new TextEncoder().encode('Hello <script>eval("pwned")</script>');
    const { threats } = analyzeScripts(text, "notes.txt", "application/octet-stream");
    expect(threats.length).toBeGreaterThan(0);
    expect(threats.some((t) => t.category === "hidden_content")).toBe(true);
  });

  it("returns clean for normal PDF", () => {
    const text = new TextEncoder().encode("%PDF-1.4 /Page /MediaBox [0 0 612 792]");
    const { threats } = analyzeScripts(text, "clean.pdf", "application/pdf");
    expect(threats).toHaveLength(0);
  });
});

describe("polyglot", () => {
  it("returns clean for normal files", () => {
    const png = new Uint8Array(2000).fill(0);
    png[0] = 0x89; png[1] = 0x50; png[2] = 0x4e; png[3] = 0x47;
    const { isPolyglot } = analyzePolyglot(png, "image.png", "image/png");
    expect(isPolyglot).toBe(false);
  });

  it("detects embedded executable in image", () => {
    const data = new Uint8Array(5000).fill(0);
    data[0] = 0x89; data[1] = 0x50; data[2] = 0x4e; data[3] = 0x47;
    data[1024] = 0x4d; data[1025] = 0x5a;
    const { isPolyglot, threats } = analyzePolyglot(data, "image.png", "image/png");
    expect(isPolyglot).toBe(true);
    expect(threats[0].severity).toBe("critical");
    expect(threats[0].category).toBe("polyglot_file");
  });
});

describe("structure", () => {
  it("flags empty files", () => {
    const { threats, structureValid } = analyzeStructure(
      new Uint8Array(0),
      "empty.txt",
      "text/plain",
    );
    expect(structureValid).toBe(false);
    expect(threats[0].category).toBe("suspicious_metadata");
  });

  it("detects zip bomb by entry count", () => {
    const entries = 15000;
    const data = new Uint8Array(entries * 4);
    for (let i = 0; i < entries; i++) {
      const offset = i * 4;
      data[offset] = 0x50;
      data[offset + 1] = 0x4b;
      data[offset + 2] = 0x03;
      data[offset + 3] = 0x04;
    }
    const { threats } = analyzeStructure(data, "bomb.zip", "application/zip");
    expect(threats.some((t) => t.category === "zip_bomb")).toBe(true);
  });
});
