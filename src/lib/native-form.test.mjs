import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formFieldError, formFieldValue, formResponse, initialFormDraft, safeFormImageSource, setFormOther, toggleFormOption } from './native-form.ts';

const option = (value, checked = false, disabled = false) => ({ value, label: [{ text: `Label ${value}` }], checked, disabled });
const choice = (name, options, overrides = {}) => ({ kind: 'choice', name, label: [], multi: false, select: false, other: false, required: false, options, ...overrides });
const text = (name, value, overrides = {}) => ({ kind: 'text', name, label: [], type: 'text', value, multiline: false, placeholder: '', rows: 1, required: false, ...overrides });
const form = (fields, hidden = []) => ({ fields, hidden, sections: [{ title: [], fieldset: false, blocks: fields.map(field => ({ kind: 'field', field })) }] });

test('native defaults preserve hidden values, numeric types, last checked radio, disabled omission, and single checkbox scalar', () => {
  const model = form([
    text('count', '2.5', { type: 'number' }), text('empty', '', { type: 'range' }), text('message', 'line 1\nline 2', { multiline: true }),
    choice('radio', [option('first', true), option('last', true)]),
    choice('check', [option('yes', true)], { multi: true }),
    choice('unchecked', [option('no')], { multi: true }),
    choice('many', [option('a', true), option('b', true, true), option('c', true)], { multi: true }),
    choice('none', [option('x'), option('y')], { multi: true, select: true }),
    text('', 'unnamed'),
  ], [['hidden', 'secret'], ['__proto__', 'safe own key']]);
  const result = formResponse(model, initialFormDraft(model));
  assert.deepEqual(result.data, Object.fromEntries([
    ['hidden', 'secret'], ['__proto__', 'safe own key'], ['count', 2.5], ['empty', ''], ['message', 'line 1\nline 2'],
    ['radio', 'last'], ['check', 'yes'], ['many', ['a', 'c']], ['none', []],
  ]));
  assert.equal(Object.getPrototypeOf(result.data), Object.prototype);
  assert.equal(result.notes, undefined);
});

test('Other follows native radio replacement and checkbox additive semantics without discarding drafts', () => {
  const single = choice('radio', [option('a', true), option('b')], { other: true });
  let draft = initialFormDraft(form([single]))[0];
  draft = setFormOther(single, draft, '  custom answer  ');
  assert.deepEqual(draft.selected, []);
  assert.equal(formFieldValue(single, draft), 'custom answer');
  draft = toggleFormOption(single, draft, 1);
  assert.equal(formFieldValue(single, draft), 'b');
  assert.equal(draft.other, '  custom answer  ', 'native Other draft survives picking an option');
  draft = setFormOther(single, draft, 'new answer');
  assert.equal(formFieldValue(single, draft), 'new answer');
  const multi = { ...single, multi: true };
  draft = initialFormDraft(form([multi]))[0];
  draft = setFormOther(multi, draft, ' custom ');
  assert.deepEqual(formFieldValue(multi, draft), ['a', 'custom']);
});

test('option notes submit only selected enabled options with native submitted values and trimmed text', () => {
  const field = choice('pick', [option('a', true), option('b'), option('disabled', false, true)], { multi: true, question: 'Which option?' });
  const model = form([field]);
  const drafts = initialFormDraft(model);
  drafts[0].notes = { 0: ' note for A ', 1: 'draft for B', 2: 'not allowed' };
  assert.deepEqual(formResponse(model, drafts), { data: { pick: ['a'] }, notes: [{ name: 'pick', question: 'Which option?', option: 'Label a', value: 'a', text: 'note for A' }] });
  assert.equal(toggleFormOption(field, drafts[0], 2), drafts[0]);
  drafts[0] = toggleFormOption(field, drafts[0], 1);
  assert.equal(formResponse(model, drafts).notes[1].text, 'draft for B');
  drafts[0] = toggleFormOption(field, drafts[0], 0);
  assert.deepEqual(formResponse(model, drafts).notes, [{ name: 'pick', question: 'Which option?', option: 'Label b', value: 'b', text: 'draft for B' }]);
});

test('notes disambiguate native options sharing a submitted value', () => {
  const field = choice('duplicate', [{ ...option('same', true), label: [{ text: 'First option' }] }, { ...option('same', true), label: [{ text: 'Second option' }] }], { multi: true, question: 'Choose duplicates' });
  const model = form([field]), drafts = initialFormDraft(model);
  drafts[0].notes = { 0: 'first note', 1: 'second note' };
  const response = formResponse(model, drafts);
  assert.deepEqual(response.data.duplicate, ['same', 'same']);
  assert.deepEqual(response.notes.map(note => [note.question, note.option, note.text]), [['Choose duplicates', 'First option', 'first note'], ['Choose duplicates', 'Second option', 'second note']]);
});

test('native field validation handles required, numeric bounds, lengths, email, URLs and anchored patterns', () => {
  assert.equal(formFieldError(text('x', '', { required: true }), '  '), 'Required');
  assert.equal(formFieldError(choice('x', [option('a'), option('b')], { required: true, multi: true }), []), 'Select at least one');
  assert.equal(formFieldError(text('x', '', { type: 'number' }), 'NaN'), 'Enter a number');
  assert.equal(formFieldError(text('x', '', { type: 'range', min: 2 }), 1), 'Must be at least 2');
  assert.equal(formFieldError(text('x', '', { type: 'number', max: 4 }), 5), 'Must be at most 4');
  assert.equal(formFieldError(text('x', '', { minLength: 2 }), 'x'), 'Needs at least 2 characters');
  assert.equal(formFieldError(text('x', '', { maxLength: 2 }), 'xxx'), 'At most 2 characters');
  assert.equal(formFieldError(text('x', '', { type: 'email' }), 'a@b'), undefined, 'match SDK, not stricter browser email rules');
  assert.equal(formFieldError(text('x', '', { type: 'email' }), 'invalid'), 'Enter an email address');
  assert.equal(formFieldError(text('x', '', { type: 'url' }), '/relative'), 'Enter a full URL');
  assert.equal(formFieldError(text('x', '', { pattern: '[a-z]+' }), 'abc1'), 'Must match [a-z]+');
  assert.equal(formFieldError(text('x', '', { pattern: '[' }), 'anything'), undefined, 'SDK ignores malformed patterns');
  const model = form([text('missing', '', { required: true })]);
  assert.throws(() => formResponse(model, initialFormDraft(model)), /missing: Required/);
});

test('only resolved image data is displayed, never model URLs, file paths or executable documents', () => {
  for (const src of [undefined, 'javascript:alert(1)', 'file:///secret', '../secret.png', 'https://example.com/tracker.png', 'data:text/html,<script>alert(1)</script>']) assert.equal(safeFormImageSource(src), undefined);
  for (const src of ['data:image/png;base64,aGVsbG8=', 'data:image/svg+xml;charset=utf-8,%3Csvg%3E%3C%2Fsvg%3E']) assert.equal(safeFormImageSource(src), src);
});
