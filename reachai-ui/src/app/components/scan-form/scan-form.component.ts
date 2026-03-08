import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScanService } from '../../services/scan.service';
import { ScanRequest, ScanResponse } from '../../models/scan.model';

@Component({
  selector: 'app-scan-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scan-form.component.html',
  styleUrls: ['./scan-form.component.css']
})
export class ScanFormComponent {
  repoUrl: string = '';
  isScanning: boolean = false;
  scanComplete: boolean = false;
  scanResults: ScanResponse | null = null;
  errorMessage: string = '';

  constructor(private scanService: ScanService) { }

  onSubmit(): void {
    if (!this.repoUrl.trim()) {
      this.errorMessage = 'Please enter a repository URL';
      return;
    }

    this.isScanning = true;
    this.scanComplete = false;
    this.errorMessage = '';
    this.scanResults = null;

    const request: ScanRequest = {
      repoUrl: this.repoUrl.trim()
    };

    this.scanService.performScan(request).subscribe({
      next: (response) => {
        this.scanResults = response;
        this.isScanning = false;
        this.scanComplete = true;
      },
      error: (error) => {
        this.errorMessage = error.message || 'Failed to perform scan. Please try again.';
        this.isScanning = false;
        this.scanComplete = false;
      }
    });
  }

  resetForm(): void {
    this.repoUrl = '';
    this.scanComplete = false;
    this.scanResults = null;
    this.errorMessage = '';
  }
}