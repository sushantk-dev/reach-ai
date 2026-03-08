import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, retry } from 'rxjs/operators';
import { ScanRequest, ScanResponse } from '../models/scan.model';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ScanService {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) { }

  /**
   * Triggers a vulnerability scan for the given repository
   */
  performScan(request: ScanRequest): Observable<ScanResponse> {
    return this.http.post<ScanResponse>(`${this.apiUrl}/api/scans`, request)
      .pipe(
        retry(1),
        catchError(this.handleError)
      );
  }

  /**
   * Checks if the backend API is healthy
   */
  healthCheck(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/scans/health`)
      .pipe(
        catchError(this.handleError)
      );
  }

  /**
   * Error handler
   */
  private handleError(error: HttpErrorResponse) {
    let errorMessage = 'An unknown error occurred';

    if (error.error instanceof ErrorEvent) {
      // Client-side error
      errorMessage = `Error: ${error.error.message}`;
    } else {
      // Server-side error
      errorMessage = `Server returned code ${error.status}, error message: ${error.message}`;
    }

    console.error(errorMessage);
    return throwError(() => new Error(errorMessage));
  }
}