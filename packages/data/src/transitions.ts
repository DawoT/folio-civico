import { getCommissionSummary } from "./commissions";
import { getObservationForMember, ReviewAccessError, type ReviewMetadata, type SavedObservation } from "./review";

export type ObservationAction = "submit" | "validate" | "dismiss";
export interface TransitionInput {
  commissionId: string;
  observationId: string;
  subject: string;
  action: ObservationAction;
  requestKey: string;
  note?: string;
}

export class ReviewConflictError extends Error {}

export async function transitionObservation(
  db: D1Database, input: TransitionInput
): Promise<{ observation: SavedObservation & ReviewMetadata; replayed: boolean }> {
  if (!/^[A-Za-z0-9_-]{8,96}$/.test(input.requestKey)) {
    throw new ReviewConflictError("Invalid transition idempotency key");
  }
  const submitted = input.action === "submit";
  const note = submitted ? null : input.note?.trim() ?? null;
  if (!submitted && (!note || note.length < 15 || note.length > 1000)) {
    throw new ReviewConflictError("A substantive reviewer rationale is required");
  }
  const membership = await getCommissionSummary(db, input.subject, input.commissionId);
  if (!membership || membership.status !== "active") throw new ReviewAccessError("Commission not accessible or closed");

  if (submitted && membership.role === "observer") {
    throw new ReviewAccessError("Observer cannot submit reviews");
  }
  if (!submitted && membership.role !== "member" && membership.role !== "president") {
    throw new ReviewAccessError("Only a commission member or president can decide");
  }

  const initial=await getObservationForMember(db,input.subject,input.commissionId,input.observationId);
  if (!initial) throw new ReviewAccessError("Observation not found");
  if (submitted && initial.authorSubject !== input.subject) {
    throw new ReviewAccessError("Only the author can submit this draft");
  }
  if (!submitted && initial.authorSubject === input.subject) {
    throw new ReviewAccessError("Author cannot review own observation");
  }

  const destination=submitted ? "in_review" : input.action === "validate" ? "validated" : "dismissed";
  const expected=submitted ? "draft" : "in_review";

  function isReplay(value: SavedObservation & ReviewMetadata): boolean {
    return value.status === destination && (
      submitted
        ? value.submittedBy === input.subject && value.submitRequestKey === input.requestKey
        : value.reviewedBy === input.subject && value.reviewRequestKey === input.requestKey
          && value.reviewNote === note
    );
  }

  if (isReplay(initial)) return { observation: initial, replayed: true };
  if (initial.status !== expected) throw new ReviewConflictError("Observation state has changed");

  const statement = submitted
    ? db.prepare(`
        UPDATE observations
        SET status='in_review',submitted_by=?,submitted_at=CURRENT_TIMESTAMP,submit_request_key=?
        WHERE id=? AND commission_id=? AND status='draft' AND author_subject=?
      `).bind(input.subject,input.requestKey,input.observationId,input.commissionId,input.subject)
    : db.prepare(`
        UPDATE observations
        SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,review_note=?,
          review_request_key=?,
          validated_by=CASE WHEN ?='validated' THEN ? ELSE NULL END,
          validated_at=CASE WHEN ?='validated' THEN CURRENT_TIMESTAMP ELSE NULL END
        WHERE id=? AND commission_id=? AND status='in_review' AND author_subject<>?
      `).bind(destination,input.subject,note,input.requestKey,
        destination,input.subject,destination,input.observationId,input.commissionId,input.subject);

  try {
    const result=await statement.run();
    if (result.meta.changes !== 1) throw new ReviewConflictError("Observation changed during review");
  } catch (error) {
    const latest=await getObservationForMember(db,input.subject,input.commissionId,input.observationId);
    if (latest && isReplay(latest)) return {observation:latest,replayed:true};
    if (error instanceof ReviewConflictError) throw error;
    throw new ReviewConflictError("Transition rejected by evidence or authorization constraints");
  }
  const current=await getObservationForMember(db,input.subject,input.commissionId,input.observationId);
  if (!current) throw new ReviewAccessError("Observation no longer visible");
  return {observation:current,replayed:false};
}
