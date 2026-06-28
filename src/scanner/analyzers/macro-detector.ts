import type { Threat } from "../../types";

const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

const DANGEROUS_OLE_STREAMS = [
  "VBA",
  "Macros",
  "_VBA_PROJECT",
  "VBAProject",
  "ThisDocument",
  "Module",
  "powershell",
  "cmd.exe",
  "wscript",
  "cscript",
];

const MACRO_PATTERNS = [
  { pattern: "Auto_Open", severity: "high" as const, desc: "Auto-executing macro (Auto_Open)" },
  { pattern: "AutoOpen", severity: "high" as const, desc: "Auto-executing macro (AutoOpen)" },
  { pattern: "AutoExec", severity: "high" as const, desc: "Auto-executing macro (AutoExec)" },
  { pattern: "Document_Open", severity: "high" as const, desc: "Auto-executing macro (Document_Open)" },
  { pattern: "Workbook_Open", severity: "high" as const, desc: "Auto-executing macro (Workbook_Open)" },
  { pattern: "Shell", severity: "high" as const, desc: "Shell command execution in macro" },
  { pattern: "WScript.Shell", severity: "critical" as const, desc: "Windows Script Host Shell access" },
  { pattern: "Scripting.FileSystemObject", severity: "critical" as const, desc: "File system access in macro" },
  { pattern: "CreateObject", severity: "medium" as const, desc: "COM object creation in macro" },
  { pattern: "PowerShell", severity: "critical" as const, desc: "PowerShell invocation from macro" },
  { pattern: "cmd /c", severity: "critical" as const, desc: "Command prompt invocation from macro" },
  { pattern: "ADODB.Stream", severity: "high" as const, desc: "Binary stream manipulation in macro" },
  { pattern: "URLDownloadToFile", severity: "critical" as const, desc: "Remote file download capability" },
];

function searchBytes(data: Uint8Array, pattern: string): boolean {
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

export function analyzeMacros(
  data: Uint8Array,
  fileName: string,
): { threats: Threat[]; hasMacros: boolean } {
  const threats: Threat[] = [];
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
        location: fileName,
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
        signature: pattern,
      });
    }
  }

  if (isOle && isLegacyOffice && !hasMacros) {
    threats.push({
      category: "macro_embedded",
      severity: "low",
      description: "Legacy Office format (OLE2) — may contain macros that could not be fully parsed client-side.",
      location: fileName,
    });
  }

  return { threats, hasMacros };
}
