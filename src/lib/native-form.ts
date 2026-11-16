import type { NativeForm, NativeFormChoice, NativeFormField, NativeFormResponse, NativeFormSpan, NativeFormValue } from "./api";

export interface NativeFormFieldDraft {
  text: string; selected: number[]; other: string; notes: Record<number, string>;
}
export const formSpanText = (spans: readonly NativeFormSpan[]): string => spans.map(span => span.text).join("");
export function initialFormDraft(form: NativeForm | undefined): NativeFormFieldDraft[] {
  return (form?.fields ?? []).map(field => {
    const selected = field.kind === "choice" ? field.options.flatMap((option, index) => option.checked ? [index] : []) : [];
    return { text: field.kind === "text" ? field.value : "", selected: field.kind === "choice" && !field.multi ? selected.slice(-1) : selected, other: "", notes: {} };
  });
}
export function toggleFormOption(field: NativeFormChoice, draft: NativeFormFieldDraft, index: number): NativeFormFieldDraft {
  if (!field.options[index] || field.options[index].disabled) return draft;
  return { ...draft, selected: !field.multi ? [index] : draft.selected.includes(index) ? draft.selected.filter(at => at !== index) : [...draft.selected, index] };
}
export function setFormOther(field: NativeFormChoice, draft: NativeFormFieldDraft, other: string): NativeFormFieldDraft {
  return { ...draft, other, selected: !field.multi && other !== draft.other && other.trim() ? [] : draft.selected };
}
export function formFieldValue(field: NativeFormField, draft: NativeFormFieldDraft): NativeFormValue | undefined {
  if (field.kind === "text") {
    if ((field.type === "number" || field.type === "range") && draft.text.trim() !== "" && Number.isFinite(Number(draft.text))) return Number(draft.text);
    return draft.text;
  }
  const values = field.options.flatMap((option, index) => draft.selected.includes(index) && !option.disabled ? [option.value] : []);
  const other = field.other && (field.multi || draft.selected.length === 0) ? draft.other.trim() : "";
  if (field.multi && field.options.length > 1) return other ? [...values, other] : values;
  return other || values[0];
}
// Match pi-tui/html-form/data.ts rather than browser validity rules (which coerce dates,
// range defaults, step increments and URL/email formats differently from the native UI).
export function formFieldError(field: NativeFormField, value: NativeFormValue | undefined): string | undefined {
  if (field.kind === "choice") {
    if (!field.required || !(value === undefined || (Array.isArray(value) && !value.length))) return undefined;
    return field.multi && field.options.length > 1 ? "Select at least one" : "Required";
  }
  const text = value === undefined ? "" : String(value);
  if (text.trim() === "") return field.required ? "Required" : undefined;
  if (field.type === "number" || field.type === "range") {
    const number = Number(text);
    if (!Number.isFinite(number)) return "Enter a number";
    if (field.min !== undefined && number < field.min) return `Must be at least ${field.min}`;
    if (field.max !== undefined && number > field.max) return `Must be at most ${field.max}`;
  }
  if (field.minLength !== undefined && text.length < field.minLength) return `Needs at least ${field.minLength} characters`;
  if (field.maxLength !== undefined && text.length > field.maxLength) return `At most ${field.maxLength} characters`;
  if (field.type === "email" && !/^[^\s@]+@[^\s@]+$/.test(text)) return "Enter an email address";
  if (field.type === "url") {
    try { new URL(text); } catch { return "Enter a full URL"; }
  }
  if (field.pattern) {
    let pattern: RegExp | undefined;
    try { pattern = new RegExp(`^(?:${field.pattern})$`, "v"); } catch { /* Native SDK ignores invalid patterns. */ }
    if (pattern?.test(text) === false) return `Must match ${field.pattern.length > 40 ? `${field.pattern.slice(0, 39)}…` : field.pattern}`;
  }
  return undefined;
}
export function formResponse(form: NativeForm, drafts: readonly NativeFormFieldDraft[]): NativeFormResponse {
  const entries: [string, NativeFormValue][] = [...form.hidden];
  const notes: NonNullable<NativeFormResponse["notes"]> = [];
  form.fields.forEach((field, index) => {
    const draft = drafts[index];
    if (!draft) throw new Error("Missing native form draft");
    const value = formFieldValue(field, draft);
    const error = formFieldError(field, value);
    if (error) throw new Error(`${formSpanText(field.label) || field.name || `Field ${index + 1}`}: ${error}`);
    if (!field.name) return;
    if (value !== undefined) entries.push([field.name, value]);
    if (field.kind === "choice") field.options.forEach((option, at) => {
      const text = draft.notes[at]?.trim();
      if (text && !option.disabled && draft.selected.includes(at)) notes.push({
        name: field.name, ...(field.question !== undefined ? { question: field.question } : {}),
        option: formSpanText(option.label).replace(/\t/g, " ").replace(/[\x00-\x09\x0b-\x1f\x7f]/g, "").replace(/\s+/g, " ").trim() || option.value,
        value: option.value, text,
      });
    });
  });
  return { data: Object.fromEntries(entries), ...(notes.length ? { notes } : {}) };
}
/** Only bridge-resolved images: never fetch agent URLs or insert model markup in the live DOM. */
export function safeFormImageSource(src: string | undefined): string | undefined {
  return src && /^data:image\/(?:png|jpeg|jpg|gif|webp|avif|bmp|svg\+xml)(?:;|,)/i.test(src) ? src : undefined;
}
