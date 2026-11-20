import type { ChecklistRow } from "../api";

export type ChecklistAreaFilter = "all" | ChecklistRow["area"];
export type ChecklistStatusFilter = "all" | "pending" | "validated" | "located" | "other";
export type ChecklistStatusCounts = Record<ChecklistStatusFilter, number>;

export function isInternallyValidated(row: ChecklistRow): boolean {
  return row.statusSource === "validated_search"
    && typeof row.validatedSearchObservationId === "string"
    && row.validatedSearchObservationId.length > 0;
}

/** Only filters already-authorized checklist rows; never alters backend state. */
export function filterChecklistRows(
  rows: readonly ChecklistRow[], status: ChecklistStatusFilter, area: ChecklistAreaFilter
): ChecklistRow[] {
  return rows.filter(row => {
    if (area !== "all" && row.area !== area) return false;
    if (status === "all") return true;
    if (status === "validated") return isInternallyValidated(row);
    if (status === "pending") return row.status === "pending" && !isInternallyValidated(row);
    if (status === "located") return row.status === "located" && !isInternallyValidated(row);
    return !isInternallyValidated(row) && row.status !== "pending" && row.status !== "located";
  });
}

export function countChecklistByStatus(
  rows: readonly ChecklistRow[], area: ChecklistAreaFilter
): ChecklistStatusCounts {
  const selected = filterChecklistRows(rows, "all", area);
  return {
    all: selected.length,
    pending: filterChecklistRows(selected, "pending", "all").length,
    validated: filterChecklistRows(selected, "validated", "all").length,
    located: filterChecklistRows(selected, "located", "all").length,
    other: filterChecklistRows(selected, "other", "all").length
  };
}

export interface ChecklistFiltersProps {
  selectedStatus: ChecklistStatusFilter;
  selectedArea: ChecklistAreaFilter;
  counts: ChecklistStatusCounts;
  onStatusChange: (next: ChecklistStatusFilter) => void;
  onAreaChange: (next: ChecklistAreaFilter) => void;
}

const filters: Array<[ChecklistStatusFilter, string]> = [
  ["all", "Todos"],
  ["pending", "Pendientes"],
  ["validated", "Validación interna"],
  ["located", "Ubicados"],
  ["other", "Otros estados"]
];

export function ChecklistFilters({
  selectedStatus, selectedArea, counts, onStatusChange, onAreaChange
}: ChecklistFiltersProps) {
  return (
    <div className="checklist-filters">
      <label htmlFor="checklist-filter-area" className="checklist-filter-area">
        Área del checklist para filtrar
        <select id="checklist-filter-area" value={selectedArea}
          onChange={event => onAreaChange(event.target.value as ChecklistAreaFilter)}>
          <option value="all">Todas las áreas</option>
          <option value="works">Obras</option>
          <option value="procurement">Contrataciones</option>
        </select>
      </label>
      <div role="group" className="checklist-filter-actions"
        aria-label="Filtrar ítems del checklist">
        {filters.map(([key, label]) => (
          <button key={key} type="button" className="checklist-filter-button"
            aria-pressed={selectedStatus === key}
            onClick={() => onStatusChange(key)}>
            {label} ({counts[key]})
          </button>
        ))}
      </div>
      <p className="checklist-filter-note">
        Solo ítems cargados de la comisión. Los filtros no modifican el checklist
        ni constituyen una validación oficial.
      </p>
    </div>
  );
}
