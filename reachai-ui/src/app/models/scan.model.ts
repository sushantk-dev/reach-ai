// TypeScript interfaces matching the Java backend models

export interface Dependency {
  groupId: string;
  artifactId: string;
  version: string;
}

export interface CallStep {
  fileName: string;
  lineNumber: number;
  methodName: string;
  className: string;
  snippet: string;
}

export interface CallChain {
  entryPoint: string;
  vulnerableSink: string;
  steps: CallStep[];
  isReachable: boolean;
}

export interface ExploitDemo {
  attackSetup: string;
  httpRequest: string;
  stepByStep: string[];
  attackerOutcome: string;
  unsafeCode: string;
  safeCode: string;
}

export interface VulnerableDependency {
  dependency: Dependency;
  cveId: string;
  description: string;
  severity: string;
  reachable: boolean | null;
  reachabilityStatus: string;
  callChains: CallChain[];
  verdict: string;
  confidenceScore: number;
  confidenceReasoning: string;
  plainEnglishExplanation: string;
  attackNarrative: string;
  exploitDemo: ExploitDemo | null;
}

export interface ScanRequest {
  repoUrl: string;
}

export interface ScanResponse {
  repoUrl: string;
  scanTime: string;
  totalDependencies: number;
  vulnerableDependencies: number;
  vulnerabilities: VulnerableDependency[];
}