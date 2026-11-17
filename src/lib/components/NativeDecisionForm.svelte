<script lang="ts">
  import type { NativeForm, NativeFormSpan } from "../api";
  import { formFieldError, formFieldValue, formSpanText, safeFormImageSource, setFormOther, toggleFormOption, type NativeFormFieldDraft } from "../native-form";

  let { form, drafts, id, showErrors = false, onChange, onSubmit }: {
    form: NativeForm; drafts: readonly NativeFormFieldDraft[]; id: string; showErrors?: boolean;
    onChange: (index: number, update: (draft: NativeFormFieldDraft) => NativeFormFieldDraft) => void;
    onSubmit: () => void;
  } = $props();
  const sections = $derived.by(() => {
    let index = 0;
    return form.sections.map(section => ({ ...section, blocks: section.blocks.map(block => ({ block, index: block.kind === "field" ? index++ : -1 })) }));
  });
</script>

{#snippet spans(parts: readonly NativeFormSpan[])}
  {#each parts as span}{#if span.style === "strong"}<strong>{span.text}</strong>{:else if span.style === "em"}<em>{span.text}</em>{:else if span.style === "code"}<code>{span.text}</code>{:else}{span.text}{/if}{/each}
{/snippet}

<div class="native-form">
  {#each sections as section, sectionIndex}
    <section class:grouped={section.fieldset} aria-label={formSpanText(section.title) || `Form section ${sectionIndex + 1}`}>
      {#if section.title.length}<h4>{@render spans(section.title)}</h4>{/if}
      {#each section.blocks as entry}
        {@const block = entry.block}
        {#if block.kind === "text"}
          {#if block.heading}<h5>{@render spans(block.spans)}</h5>{:else}<p>{@render spans(block.spans)}</p>{/if}
        {:else if block.kind === "pre"}<pre>{block.text}</pre>
        {:else if block.kind === "list"}
          {#if block.ordered}<ol>{#each block.items as item}<li>{@render spans(item)}</li>{/each}</ol>{:else}<ul>{#each block.items as item}<li>{@render spans(item)}</li>{/each}</ul>{/if}
        {:else if block.kind === "table"}
          <div class="table-scroll"><table><tbody>{#each block.rows as row, rowIndex}<tr>{#each row as cell}{#if rowIndex < block.headerRows}<th>{@render spans(cell)}</th>{:else}<td>{@render spans(cell)}</td>{/if}{/each}</tr>{/each}</tbody></table></div>
        {:else if block.kind === "image" || block.kind === "svg"}
          {@const source = safeFormImageSource(block.displaySrc)}
          <figure>{#if source}<img src={source} alt={block.alt || "Form illustration"} />{:else}<p class="media-error">{block.mediaError || "Image could not be loaded"}</p>{/if}{#if block.alt}<figcaption>{block.alt}</figcaption>{/if}</figure>
        {:else if block.kind === "field"}
          {@const field = block.field}
          {@const draft = drafts[entry.index]}
          {@const controlId = `${id}:field:${entry.index}`}
          {@const error = showErrors ? formFieldError(field, formFieldValue(field, draft)) : undefined}
          {#if field.kind === "text"}
            <label for={controlId}>{#if field.label.length}{@render spans(field.label)}{:else}{field.question || field.name || "Answer"}{/if}{#if field.required}<span class="required"> (required)</span>{/if}</label>
            {#if field.multiline}
              <textarea id={controlId} rows={Math.max(2, Math.min(20, field.rows))} placeholder={field.placeholder} value={draft.text} aria-required={field.required} aria-invalid={!!error} aria-describedby={error ? `${controlId}:error` : undefined} oninput={event => onChange(entry.index, draft => ({ ...draft, text: event.currentTarget.value }))}></textarea>
            {:else}
              <input id={controlId} type={field.type === "password" ? "password" : "text"} inputmode={field.type === "number" || field.type === "range" ? "decimal" : undefined} placeholder={field.placeholder} value={draft.text} aria-required={field.required} aria-invalid={!!error} aria-describedby={error ? `${controlId}:error` : undefined} oninput={event => onChange(entry.index, draft => ({ ...draft, text: event.currentTarget.value }))} />
            {/if}
            {#if field.min !== undefined || field.max !== undefined || field.minLength !== undefined || field.maxLength !== undefined || field.pattern}
              <p class="hint">{#if field.min !== undefined}Minimum: {field.min}. {/if}{#if field.max !== undefined}Maximum: {field.max}. {/if}{#if field.minLength !== undefined}Minimum length: {field.minLength}. {/if}{#if field.maxLength !== undefined}Maximum length: {field.maxLength}. {/if}{#if field.pattern}Pattern: {field.pattern}{/if}</p>
            {/if}
          {:else}
            <fieldset class="choice-field" aria-describedby={error ? `${controlId}:error` : undefined}>
              <legend>{#if field.label.length}{@render spans(field.label)}{:else}{field.question || field.name || "Choose"}{/if}{#if field.required}<span class="required"> (required)</span>{/if}</legend>
              {#if field.select && !field.multi}
                <select aria-label={field.question || formSpanText(field.label) || field.name || "Choose"} aria-required={field.required} aria-invalid={!!error} onchange={event => onChange(entry.index, draft => event.currentTarget.value === "" ? { ...draft, selected: [] } : toggleFormOption(field, draft, Number(event.currentTarget.value)))}>
                  <option value="" selected={!draft.selected.length}>No selection</option>
                  {#each field.options as option, index}<option value={index} selected={draft.selected.includes(index)} disabled={option.disabled}>{formSpanText(option.label) || option.value}</option>{/each}
                </select>
              {:else}
                {#each field.options as option, index}
                  <label class="choice"><input type={field.multi ? "checkbox" : "radio"} name={controlId} checked={draft.selected.includes(index)} disabled={option.disabled} onchange={() => onChange(entry.index, draft => toggleFormOption(field, draft, index))} /><span>{@render spans(option.label)}{#if !option.label.length}{option.value}{/if}</span></label>
                {/each}
              {/if}
              {#if field.other}<label>Other{#if draft.other.trim() && (field.multi || !draft.selected.length)} (selected){/if}<input type="text" value={draft.other} oninput={event => onChange(entry.index, draft => setFormOther(field, draft, event.currentTarget.value))} /></label>{/if}
              <button type="button" class="ghost" onclick={() => onChange(entry.index, draft => ({ ...draft, selected: [], other: "" }))}>Clear selection</button>
              {#each field.options as option, index}
                {#if !option.disabled && draft.selected.includes(index)}
                  <label class="note">Note for {formSpanText(option.label) || option.value}<textarea rows="2" value={draft.notes[index] ?? ""} oninput={event => onChange(entry.index, draft => ({ ...draft, notes: { ...draft.notes, [index]: event.currentTarget.value } }))}></textarea></label>
                {/if}
              {/each}
            </fieldset>
          {/if}
          {#if error}<p id={`${controlId}:error`} class="err" role="alert">{error}</p>{/if}
        {/if}
      {/each}
    </section>
  {/each}
  <button type="button" class="primary" onclick={onSubmit}>Submit answers</button>
</div>

<style>
  .native-form { width: 100%; min-width: 0; }
  section { margin: 10px 0; }
  .grouped, .choice-field { border: 1px solid var(--line); padding: 12px; min-width: 0; }
  h4, h5, p { margin: 8px 0; white-space: pre-wrap; overflow-wrap: anywhere; }
  h5 { font-size: inherit; }
  label { display: block; margin: 10px 0 5px; white-space: pre-wrap; overflow-wrap: anywhere; }
  input:not([type="checkbox"]):not([type="radio"]), textarea, select { box-sizing: border-box; width: 100%; }
  textarea { resize: vertical; }
  .choice { display: flex; align-items: baseline; gap: 8px; }
  .choice input { flex: none; width: auto; }
  .hint, .required, figcaption { color: var(--muted); font-size: 12px; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; }
  .table-scroll { overflow-x: auto; }
  table { border-collapse: collapse; }
  th, td { border: 1px solid var(--line); padding: 6px; white-space: pre-wrap; }
  figure { margin: 12px 0; }
  img { max-width: 100%; max-height: 480px; object-fit: contain; }
  .media-error { color: var(--muted); }
  .note { margin-left: 12px; }
</style>
