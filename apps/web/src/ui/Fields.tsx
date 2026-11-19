import type {
  InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes
} from "react";

interface FieldHelp {
  id: string;
  label: string;
  hint?: string;
  error?: string;
}

function descriptionIds(id: string, describedBy?: string, hint?: string, error?: string) {
  return [
    describedBy, hint ? `${id}-hint` : undefined, error ? `${id}-error` : undefined
  ].filter(Boolean).join(" ") || undefined;
}

function FieldFrame({ id, label, hint, error, children }: FieldHelp & { children: ReactNode }) {
  return (
    <div className="fc-field">
      <label htmlFor={id} className="fc-field-label">{label}</label>
      {children}
      {hint && <small className="fc-field-hint" id={`${id}-hint`}>{hint}</small>}
      {error && <small className="fc-field-error" id={`${id}-error`} role="alert">{error}</small>}
    </div>
  );
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & FieldHelp;
type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> & FieldHelp;
type TextareaProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id"> & FieldHelp;

/** Native controls remain label-bound; error and help text are read by assistive tech. */
export function Field({
  id, label, hint, error, "aria-describedby": describedBy, "aria-invalid": invalid, ...props
}: InputProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error}>
      <input {...props} id={id} aria-describedby={descriptionIds(id, describedBy, hint, error)}
        aria-invalid={error ? true : invalid} />
    </FieldFrame>
  );
}

export function SelectField({
  id, label, hint, error, "aria-describedby": describedBy, "aria-invalid": invalid,
  children, ...props
}: SelectProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error}>
      <select {...props} id={id} aria-describedby={descriptionIds(id, describedBy, hint, error)}
        aria-invalid={error ? true : invalid}>
        {children}
      </select>
    </FieldFrame>
  );
}

export function TextareaField({
  id, label, hint, error, "aria-describedby": describedBy, "aria-invalid": invalid,
  ...props
}: TextareaProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error}>
      <textarea {...props} id={id}
        aria-describedby={descriptionIds(id, describedBy, hint, error)}
        aria-invalid={error ? true : invalid} />
    </FieldFrame>
  );
}
