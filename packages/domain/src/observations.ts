import { type Evidence, validateEvidence } from "./evidence";

export interface ObservationDraft {
  commissionId: string;
  authorSubject: string;
  title: string;
  description: string;
  evidence: Evidence[];
  status: "draft";
  validatedBy: null;
}

export interface ObservationDraftInput {
  commissionId: string;
  authorSubject: string;
  title: string;
  description: string;
  evidence: unknown[];
}

export function createObservationDraft(input: ObservationDraftInput): ObservationDraft {
  for (const field of ["commissionId", "authorSubject", "title", "description"] as const) {
    if (!input[field]?.trim()) throw new Error(`Missing ${field}`);
  }
  if (!Array.isArray(input.evidence) || input.evidence.length === 0) {
    throw new Error("Observation requires verifiable evidence");
  }

  const evidence = input.evidence.map(validateEvidence);
  if (evidence.some((item) => item.commissionId !== input.commissionId)) {
    throw new Error("Cross-commission evidence is forbidden");
  }

  return {
    commissionId: input.commissionId,
    authorSubject: input.authorSubject,
    title: input.title.trim(),
    description: input.description.trim(),
    evidence,
    status: "draft",
    validatedBy: null
  };
}
