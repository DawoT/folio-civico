import type { DocumentRow } from "../api";

const processingMessages: Record<DocumentRow["extractionStatus"], {
  heading: string;
  nextStep: string;
}> = {
  pending: {
    heading: "Pendiente de procesamiento.",
    nextStep: "Esperar la inspección técnica autorizada; aún no hay texto inspeccionado para consultar."
  },
  processing: {
    heading: "Procesamiento técnico en curso.",
    nextStep: "Esperar el resultado técnico antes de consultar o citar páginas."
  },
  needs_review: {
    heading: "Revisión técnica del procesamiento requerida; no es una validación institucional.",
    nextStep: "Solicitar al responsable técnico que revise el resultado antes de usar evidencia documental."
  },
  failed: {
    heading: "El procesamiento falló.",
    nextStep: "Comunicar el fallo al responsable técnico; no hay texto inspeccionado disponible."
  },
  ready: {
    heading: "Texto inspeccionado disponible para consulta por página.",
    nextStep: "Consultar el texto inspeccionado y documentar una observación si corresponde; toda decisión requiere revisión humana independiente."
  }
};

/** Processing is technical; the original PDF remains quarantined in every state. */
export function DocumentProcessingGuidance({
  status
}: { status: DocumentRow["extractionStatus"] }) {
  const message = processingMessages[status];
  return (
    <div className="review-note document-processing-guidance" role="status">
      <p><strong>{message.heading}</strong> El PDF original permanece en cuarentena en todos los estados.</p>
      <p>Siguiente paso: {message.nextStep}</p>
    </div>
  );
}
