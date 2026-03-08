import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { ScanFormComponent } from './components/scan-form/scan-form.component';
import { ScanResultsComponent } from './components/scan-results/scan-results.component';
import { ScanResponse } from './models/scan.model';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    HttpClientModule,
    ScanFormComponent,
    ScanResultsComponent
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'ReachAI';
}