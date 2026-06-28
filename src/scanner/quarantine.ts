import type { ScanReport, QuarantineStatus, ScanVerdict } from "../types";

interface QuarantinedFile {
  file: File;
  report: ScanReport;
  quarantinedAt: string;
}

export class Quarantine {
  private held = new Map<string, QuarantinedFile>();

  add(file: File, report: ScanReport): void {
    this.held.set(report.id, {
      file,
      report,
      quarantinedAt: new Date().toISOString(),
    });
  }

  release(scanId: string): File | null {
    const entry = this.held.get(scanId);
    if (!entry) return null;

    entry.report.quarantine.status = "released";
    entry.report.quarantine.reason = "Manually released from quarantine";
    this.held.delete(scanId);
    return entry.file;
  }

  destroy(scanId: string): boolean {
    const entry = this.held.get(scanId);
    if (!entry) return false;

    entry.report.quarantine.status = "destroyed";
    entry.report.quarantine.reason = "File permanently discarded";
    this.held.delete(scanId);
    return true;
  }

  get(scanId: string): QuarantinedFile | undefined {
    return this.held.get(scanId);
  }

  getAll(): QuarantinedFile[] {
    return Array.from(this.held.values());
  }

  getReport(scanId: string): ScanReport | undefined {
    return this.held.get(scanId)?.report;
  }

  clear(): void {
    for (const entry of this.held.values()) {
      entry.report.quarantine.status = "destroyed";
    }
    this.held.clear();
  }

  get size(): number {
    return this.held.size;
  }

  shouldQuarantine(verdict: ScanVerdict, riskThreshold: number): boolean {
    if (verdict === "malicious") return true;
    if (verdict === "suspicious") return true;
    return false;
  }
}
