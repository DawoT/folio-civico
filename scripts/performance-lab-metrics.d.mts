export interface LabSample {
  ttfbMs: number;
  fcpMs: number;
  lcpMs: number;
  cls: number;
}
export function validateLabSample(sample: unknown): LabSample;
export function summarizeLabMetrics(samples: unknown[]): {
  navigations: number;
  median: LabSample;
};
