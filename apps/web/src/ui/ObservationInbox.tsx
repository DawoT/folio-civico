import type { ObservationRow } from "../api";

export type InboxFilter = "all" | "for_review" | "my_drafts" | "decided";
export type InboxObservation = Pick<ObservationRow, "status" | "canReview" | "canSubmit">;
export type InboxCounts = Record<InboxFilter, number>;

/**
 * Filters the authorized records already loaded via history pagination.
 * canReview/canSubmit are server-provided capability flags; status alone
 * must never imply permission to approve or submit a record.
 */
export function filterLoadedObservations<T extends InboxObservation>(
  records: readonly T[], selected: InboxFilter
): T[] {
  switch (selected) {
    case "for_review":
      return records.filter(row => row.status === "in_review" && row.canReview === true);
    case "my_drafts":
      return records.filter(row => row.status === "draft" && row.canSubmit === true);
    case "decided":
      return records.filter(row => row.status === "validated" || row.status === "dismissed");
    default:
      return [...records];
  }
}

export function countLoadedObservations(records: readonly InboxObservation[]): InboxCounts {
  return {
    all: records.length,
    for_review: filterLoadedObservations(records, "for_review").length,
    my_drafts: filterLoadedObservations(records, "my_drafts").length,
    decided: filterLoadedObservations(records, "decided").length
  };
}

export interface ObservationInboxFiltersProps {
  counts: InboxCounts;
  selected: InboxFilter;
  onSelect: (value: InboxFilter) => void;
  canDraft: boolean;
  hasOlderRecords: boolean;
  disabled?: boolean;
}

const filterLabels: Record<InboxFilter, string> = {
  all: "Todas",
  for_review: "Para revisar",
  my_drafts: "Mis borradores",
  decided: "Decisiones"
};

/**
 * Pressable native buttons work with keyboard and assistive technologies.
 * Counts describe the loaded subset, not the entire commission.
 */
export function ObservationInboxFilters({
  counts, selected, onSelect, canDraft, hasOlderRecords, disabled = false
}: ObservationInboxFiltersProps) {
  const enabledFilters: InboxFilter[] = canDraft
    ? ["all", "for_review", "my_drafts", "decided"]
    : ["all", "decided"];
  return (
    <div className="inbox-filters">
      <div role="group" aria-label="Filtrar observaciones cargadas" className="inbox-filter-actions">
        {enabledFilters.map(filter => (
          <button key={filter} type="button" className="inbox-filter-button"
            aria-pressed={selected === filter} disabled={disabled}
            onClick={() => onSelect(filter)}>
            {filterLabels[filter]} ({counts[filter]})
          </button>
        ))}
      </div>
      <p className="inbox-filter-note">
        Cargados: {counts.all}. Los filtros solo muestran observaciones consultadas.
        {hasOlderRecords ? " Hay más páginas sin cargar." : ""}
        {" "}No es un total de la comisión.
      </p>
    </div>
  );
}

export function inboxEmptyText(filter: InboxFilter): string {
  switch (filter) {
    case "for_review":
      return "No hay solicitudes para revisar entre las observaciones cargadas.";
    case "my_drafts":
      return "No tienes borradores pendientes de envío entre las observaciones cargadas.";
    case "decided":
      return "No hay decisiones registradas entre las observaciones cargadas.";
    default:
      return "La comisión todavía no tiene observaciones registradas.";
  }
}
