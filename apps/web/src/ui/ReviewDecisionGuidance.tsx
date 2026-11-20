/** UI-only criteria; the API remains the authority for an independent decision. */
export const REVIEW_NOTE_MIN_LENGTH = 15;
export const REVIEW_NOTE_MAX_LENGTH = 1000;

export interface ReviewDecisionProgress {
  length: number;
  remaining: number;
  enough: boolean;
  confirmed: boolean;
}

/** Match the actual server/UI decision gate's trimmed-character semantics. */
export function reviewDecisionProgress(note: string, confirmed: boolean): ReviewDecisionProgress {
  const length = note.trim().length;
  return {
    length,
    remaining: Math.max(0, REVIEW_NOTE_MIN_LENGTH - length),
    enough: length >= REVIEW_NOTE_MIN_LENGTH && length <= REVIEW_NOTE_MAX_LENGTH,
    confirmed
  };
}

/** Concise, non-live feedback: associated with the textarea via aria-describedby.
 * Frequent keystrokes must not flood a screen reader's live announcement queue.
 */
export function ReviewDecisionGuidance({
  id, note, confirmed
}: { id: string; note: string; confirmed: boolean }) {
  const state = reviewDecisionProgress(note, confirmed);
  return (
    <div className="fc-decision-guidance" id={id}>
      <p>
        {state.length > REVIEW_NOTE_MAX_LENGTH
          ? `Supera el límite de ${REVIEW_NOTE_MAX_LENGTH} caracteres.`
          : state.remaining > 0
            ? `Faltan ${state.remaining} caracteres de justificación.`
            : "Justificación con la extensión mínima requerida."}
        {" "}{state.length}/{REVIEW_NOTE_MAX_LENGTH} caracteres.
      </p>
      {!confirmed && <p>Confirma que la revisión fue independiente y asume la decisión.</p>}
      {state.enough && confirmed && (
        <p>Requisitos de formulario completos. La decisión será verificada por el servidor.</p>
      )}
    </div>
  );
}
