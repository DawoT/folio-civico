export interface TaskNavigationProps {
  hasScope: boolean;
  canDraft: boolean;
  canAdmin: boolean;
  commissionName?: string;
  batchLabel?: string;
  onOpenAdministration?: () => void;
}

/**
 * Navigates to existing document/review landmarks. Native anchors retain
 * commission+batch query parameters, browser history and keyboard support.
 * Permission-sensitive actions are hidden, never authorized in this component.
 */
export function TaskNavigation({
  hasScope, canDraft, canAdmin, commissionName, batchLabel, onOpenAdministration
}: TaskNavigationProps) {
  if (!hasScope && !canAdmin) return null;
  return (
    <nav className="task-navigation" aria-label="Áreas de trabajo">
      <div className="task-navigation-context">
        <span className="task-navigation-kicker">ÁREAS DE LA COMISIÓN</span>
        {commissionName && <strong>{commissionName}</strong>}
        {hasScope && batchLabel && <span>{batchLabel}</span>}
      </div>
      <div className="task-navigation-links">
        {hasScope && (
          <>
            <a href="#expedientes">Expedientes</a>
            <a href="#checklist">Checklist</a>
            {canDraft && <a href="#registrar-busqueda">Registrar búsqueda</a>}
            <a href="#observaciones">Observaciones</a>
            <a href="#informes">Informes</a>
          </>
        )}
        {canAdmin && <a href="#administracion" onClick={onOpenAdministration}>Administración</a>}
      </div>
    </nav>
  );
}
