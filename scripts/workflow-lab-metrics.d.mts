export type WorkflowTiming = {
  discoveryMs: number;
  openScopeMs: number;
  historyPageMs: number;
  detailOpenMs: number;
};
export interface WorkflowSample extends WorkflowTiming {
  firstPageItems: number;
  totalItems: number;
  sawSecondPage: boolean;
  sawDocument: boolean;
  sawChecklist: boolean;
  productionAssets: boolean;
  unexpectedRequests: number;
  mutations: number;
}
export function validateWorkflowSample(sample: WorkflowSample): WorkflowTiming;
export function summarizeWorkflowLab(samples: WorkflowSample[]): {
  workflows: number;
  fixture: {firstPageItems: number; totalItems: number};
  median: WorkflowTiming;
};
