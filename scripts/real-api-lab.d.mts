export interface RealApiLabSample {
  discoveryMs: number;
  openScopeMs: number;
  sessionApiMs: number;
  documentsApiMs: number;
  subject: "reviewer";
  authorized: boolean;
  productionJs: boolean;
  productionCss: boolean;
  documentReady: boolean;
  checklistReady: boolean;
  apiErrors: number;
  externalRequests: number;
  mutations: number;
  apiReads: number;
}
export type RealApiDurations = Pick<
  RealApiLabSample,
  "discoveryMs" | "openScopeMs" | "sessionApiMs" | "documentsApiMs"
>;
export interface CompiledWeb {
  html: string;
  assets: Map<string, { body: Buffer; contentType: string }>;
}
export function loadCompiledWeb(path: string): CompiledWeb;
export function compiledResponseForPath(
  pathname: string, web: CompiledWeb
): {body: string | Buffer; contentType: string} | null;
export function validateRealApiSample(sample: RealApiLabSample): RealApiDurations;
export function summarizeRealApiLab(samples: RealApiLabSample[]): {
  navigations: number;
  backend: string;
  median: RealApiDurations;
};
