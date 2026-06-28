import type { Threat } from "../../types";

const PDF_THREATS = [
  { pattern: "/JavaScript", severity: "critical" as const, desc: "JavaScript embedded in PDF" },
  { pattern: "/JS", severity: "high" as const, desc: "JavaScript action in PDF" },
  { pattern: "/Launch", severity: "critical" as const, desc: "Launch action in PDF — can execute programs" },
  { pattern: "/OpenAction", severity: "high" as const, desc: "Auto-executing action on PDF open" },
  { pattern: "/AA", severity: "medium" as const, desc: "Additional actions trigger in PDF" },
  { pattern: "/EmbeddedFile", severity: "medium" as const, desc: "Embedded file inside PDF" },
  { pattern: "/RichMedia", severity: "medium" as const, desc: "Rich media (Flash/video) embedded in PDF" },
  { pattern: "/XFA", severity: "high" as const, desc: "XFA form data — can contain scripts" },
  { pattern: "/SubmitForm", severity: "medium" as const, desc: "Form data auto-submission action" },
  { pattern: "/URI", severity: "low" as const, desc: "External URI reference in PDF" },
];

const SVG_THREATS = [
  { pattern: "<script", severity: "critical" as const, desc: "Script tag in SVG — enables XSS" },
  { pattern: "onload=", severity: "critical" as const, desc: "Event handler in SVG — enables XSS" },
  { pattern: "onclick=", severity: "critical" as const, desc: "Event handler in SVG — enables XSS" },
  { pattern: "onerror=", severity: "critical" as const, desc: "Event handler in SVG — enables XSS" },
  { pattern: "javascript:", severity: "critical" as const, desc: "JavaScript protocol in SVG" },
  { pattern: "xlink:href=\"data:", severity: "high" as const, desc: "Data URI in SVG — may embed payloads" },
  { pattern: "<foreignObject", severity: "high" as const, desc: "foreignObject in SVG — can embed HTML/scripts" },
  { pattern: "<iframe", severity: "critical" as const, desc: "iframe embedded in SVG" },
];

const HTML_THREATS = [
  { pattern: "<script", severity: "critical" as const, desc: "Script tag found — possible HTML masquerading" },
  { pattern: "javascript:", severity: "critical" as const, desc: "JavaScript protocol URI detected" },
  { pattern: "onerror=", severity: "high" as const, desc: "Error event handler — potential XSS vector" },
  { pattern: "onload=", severity: "high" as const, desc: "Load event handler — potential XSS vector" },
  { pattern: "eval(", severity: "critical" as const, desc: "eval() call detected — code execution" },
];

function textSearch(data: Uint8Array, pattern: string): boolean {
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const text = decoder.decode(data);
  return text.toLowerCase().includes(pattern.toLowerCase());
}

export function analyzeScripts(
  data: Uint8Array,
  fileName: string,
  detectedMime: string,
): { threats: Threat[]; hasScripts: boolean } {
  const threats: Threat[] = [];
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
          signature: pattern,
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
          signature: pattern,
        });
      }
    }
  }

  if (
    detectedMime === "application/octet-stream" ||
    ext === ".txt" ||
    ext === ".csv" ||
    ext === ".rtf"
  ) {
    for (const { pattern, severity, desc } of HTML_THREATS) {
      if (textSearch(data, pattern)) {
        hasScripts = true;
        threats.push({
          category: "hidden_content",
          severity,
          description: `${desc} (found in ${ext} file — possible HTML smuggling)`,
          location: fileName,
          signature: pattern,
        });
      }
    }
  }

  return { threats, hasScripts };
}
