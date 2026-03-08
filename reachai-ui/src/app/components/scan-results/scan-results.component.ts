import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanResponse, VulnerableDependency } from '../../models/scan.model';
import { AttackFlowDiagramComponent } from '../attack-flow-diagram/attack-flow-diagram.component';

@Component({
  selector: 'app-scan-results',
  standalone: true,
  imports: [CommonModule, AttackFlowDiagramComponent],
  templateUrl: './scan-results.component.html',
  styleUrls: ['./scan-results.component.css']
})
export class ScanResultsComponent {
  @Input() scanResults: ScanResponse | null = null;
  selectedVulnerability: VulnerableDependency | null = null;
  showDiagramView: boolean = false;

  selectVulnerability(vuln: VulnerableDependency): void {
    this.selectedVulnerability = vuln;
  }

  closeDetails(): void {
    this.selectedVulnerability = null;
    this.showDiagramView = false;
  }

  toggleDiagramView(): void {
    this.showDiagramView = !this.showDiagramView;
  }

  getSeverityClass(severity: string): string {
    const severityLower = severity.toLowerCase();
    return `badge-${severityLower}`;
  }

  getVerdictClass(verdict: string): string {
    const verdictLower = verdict.toLowerCase().replace('_', '-');
    return `badge-${verdictLower}`;
  }

  getConfidenceBarWidth(score: number): string {
    return `${score * 100}%`;
  }

  getConfidenceColor(score: number): string {
    if (score >= 0.9) return '#10b981';
    if (score >= 0.7) return '#3b82f6';
    if (score >= 0.5) return '#f59e0b';
    return '#ef4444';
  }
}