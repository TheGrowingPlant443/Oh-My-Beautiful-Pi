import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const NATIVE_UI_CAPTURE_ERROR = 'native_ui_capture_unavailable: Reopen this session with a compatible OMP version.';
const METHODS = ['approve', 'select', 'confirm', 'input', 'editor', 'askDialog', 'formDialog', 'custom'];
const PATCH = Symbol('omp-native-ui.raw');

// Only JSON prompt data crosses the bridge. Signals, callbacks and custom
// component factories stay on the original native invocation.
function immutable(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(immutable));
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (item !== undefined && typeof item !== 'function' && typeof item !== 'symbol') Object.defineProperty(result, key, { value: immutable(item), enumerable: true });
    }
    return Object.freeze(result);
  }
  return value;
}

const formModules = new Map();
async function prepareForm(html, captured, signal, authorizeMedia) {
  const sdk = process.env.OMP_MANAGER_SDK_DIR || process.env.OMP_SDK_DIR;
  if (!sdk) throw new Error(NATIVE_UI_CAPTURE_ERROR);
  if (!formModules.has(sdk)) formModules.set(sdk, Promise.all([
    ...['parse', 'data', 'media'].map(name => import(pathToFileURL(path.join(sdk, '..', 'pi-tui', 'src', 'html-form', `${name}.ts`)).href)),
    import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-utils/dom', sdk)).href),
  ]).then(modules => Object.assign({}, ...modules)));
  const api = await formModules.get(sdk);
  const form = api.parseHtmlForm(html);
  const questions = api.fieldQuestions(form);
  for (const field of form.fields) field.question = questions.get(field) ?? field.name;
  const sources = formMediaSources(form, api.parseHTML);
  const authorize = () => authorizeMedia?.(sources, captured);
  authorize();
  await Promise.all(form.sections.flatMap(section => section.blocks).map(async block => {
    if (block.kind !== 'image' && block.kind !== 'svg') return;
    try {
      const media = block.kind === 'svg' ? api.svgMedia(block.markup) : await api.loadFormImage(block.src, { cwd: captured.cwd, signal });
      block.displaySrc = `data:${media.mime};base64,${Buffer.from(media.bytes).toString('base64')}`;
    } catch (error) { block.mediaError = String(error.message ?? error); }
  }));
  const snapshot = immutable(form);
  return { fields: { html, form: snapshot, defaults: api.defaultFormData(form), supportsChat: false, acceptImages: false },
    authorize, answer: response => formAnswer(snapshot, response, api) };
}

// A form's native renderer loads its own copy too; authorize the complete resource graph before either surface opens.
function formMediaSources(form, parseHTML) {
  const sources = new Set();
  function source(src, depth) {
    if (!/^data:/i.test(src)) { if (src && !src.startsWith('#')) sources.add(src); return; }
    const comma = src.indexOf(',');
    if (comma < 0) return;
    let text;
    try {
      text = /;base64$/i.test(src.slice(5, comma))
        ? new TextDecoder().decode(Buffer.from(src.slice(comma + 1), 'base64'))
        : decodeURIComponent(src.slice(comma + 1));
    } catch { return; } // The SDK rejects malformed inline data without reading anything.
    if (/<svg[\s>]/i.test(text)) svg(text, depth + 1);
  }
  function svg(markup, depth) {
    if (depth > 8) { sources.add('svg-resource:recursive-data'); return; }
    if (/<!DOCTYPE|<!ENTITY|<\?xml-stylesheet/i.test(markup)) sources.add('svg-resource:external-declaration');
    const document = parseHTML(markup).document;
    for (const element of document.querySelectorAll('*')) {
      const tag = element.localName.toLowerCase();
      if (['style', 'script', 'foreignobject', 'animate', 'animatemotion', 'animatetransform', 'set'].includes(tag)) sources.add(`svg-resource:${tag}`);
      for (const attribute of element.attributes) {
        const name = attribute.name.toLowerCase(), value = attribute.value.trim();
        if (['href', 'src'].includes(name.split(':').at(-1)) || name === 'xml:base') source(value, depth);
        // Styles and escaped/resource-valued presentation attributes need read authority, not a permissive CSS regex.
        if (name === 'style' || /\\|url\s*\(/i.test(value)) sources.add('svg-resource:style');
      }
    }
  }
  for (const section of form.sections) for (const block of section.blocks) {
    if (block.kind === 'image') source(block.src, 0);
    else if (block.kind === 'svg') svg(block.markup, 0);
  }
  return Object.freeze([...sources]);
}

function formAnswer(form, response, api) {
  if (response?.cancelled === true) return undefined;
  if (!response || !response.data || typeof response.data !== 'object' || Array.isArray(response.data) ||
      Object.keys(response).some(key => !['data', 'notes'].includes(key))) throw new Error('invalid native form answer');
  const fields = new Map(form.fields.filter(field => field.name).map(field => [field.name, field]));
  const hidden = Object.fromEntries(form.hidden);
  const data = Object.fromEntries(form.hidden);
  for (const name of Object.keys(response.data)) {
    if (!fields.has(name) && (!Object.hasOwn(hidden, name) || response.data[name] !== hidden[name])) throw new Error('invalid native form field');
  }
  for (const [name, field] of fields) {
    const value = Object.hasOwn(response.data, name) ? response.data[name] : undefined;
    if (field.kind === 'text') {
      if (typeof value !== 'string' && !(typeof value === 'number' && Number.isFinite(value) && ['number', 'range'].includes(field.type))) throw new Error('invalid native form text');
      if (api.textValue(field, String(value)) !== value) throw new Error('invalid native form number');
    } else {
      const array = api.isArrayChoice(field);
      // An unchecked scalar choice leaves its same-name hidden input in the SDK's merged data.
      if (!array && Object.hasOwn(hidden, name) && value === hidden[name] && api.fieldError(field, undefined) === undefined) continue;
      if (value !== undefined && (array ? !Array.isArray(value) : typeof value !== 'string')) throw new Error('invalid native form selection');
      const values = value === undefined ? [] : array ? value : [value];
      let others = 0;
      const remaining = new Map();
      for (const option of field.options) if (!option.disabled) remaining.set(option.value, (remaining.get(option.value) ?? 0) + 1);
      for (const selected of values) {
        if (typeof selected !== 'string') throw new Error('invalid native form selection');
        const count = remaining.get(selected) ?? 0;
        if (count) remaining.set(selected, count - 1);
        else if (!field.other || !selected.trim() || selected !== selected.trim() || ++others > 1) throw new Error('invalid native form option');
      }
    }
    const error = api.fieldError(field, value);
    if (error) throw new Error(`${name}: ${error}`);
    if (value !== undefined) Object.defineProperty(data, name, { value: Array.isArray(value) ? [...value] : value, enumerable: true, writable: true, configurable: true });
  }
  if (response.notes !== undefined && !Array.isArray(response.notes)) throw new Error('invalid native form notes');
  const notes = [];
  for (const note of response.notes ?? []) {
    const candidates = form.fields.filter(field => field.name === note?.name && field.kind === 'choice' && (note.question === undefined || note.question === field.question))
      .flatMap(field => field.options.filter(option => !option.disabled && option.value === note.value).map(option =>
        ({ name: field.name, question: field.question, option: api.spansText(option.label).replace(/\t/g, ' ').replace(/[\x00-\x09\x0b-\x1f\x7f]/g, '').replace(/\s+/g, ' ').trim() || option.value, value: option.value })))
      .filter(option => note.option === undefined || option.option === note.option);
    const selected = data[note?.name];
    if (!candidates.length || typeof note.text !== 'string' || !(Array.isArray(selected) ? selected.includes(note.value) : selected === note.value) ||
        candidates.some(option => option.option !== candidates[0].option || option.question !== candidates[0].question)) throw new Error('invalid native form note');
    if (note.text.trim()) notes.push({ ...candidates[0], text: note.text.trim() });
  }
  return { data, ...(notes.length ? { notes } : {}) };
}
// Why a mapped SRS question ends without a persisted human answer; null means a real submitted answer.
function retirementReason(source, options, value, error) {
  if (source === 'retired') return 'retired';
  if (options.signal?.aborted) return 'aborted';
  if (error) return 'failed';
  if (value?.kind === 'chat') return 'chat';
  if (value?.timedOut === true || value?.results?.some(result => result.timedOut === true)) return 'timeout';
  return value?.kind === 'submit' || value?.data ? null : 'cancelled';
}
function promptFields(method, args, options) {
  const fields = {};
  if (method === 'approve') fields.prompt = args[0];
  if (method === 'select') { fields.title = args[0]; fields.options = args[1]; }
  if (method === 'confirm') { fields.title = args[0]; fields.message = args[1]; }
  if (method === 'input') { fields.title = args[0]; fields.placeholder = args[1]; }
  if (method === 'editor') { fields.title = args[0]; fields.prefill = args[1]; }
  if (method === 'askDialog') { fields.questions = args[0]; fields.acceptImages = options.acceptImages ?? false; fields.supportsChat = true; }
  if (method === 'custom') fields.title = 'Native custom dialog';
  for (const key of ['timeout', 'secret', 'initialIndex', 'disabledIndices', 'outline', 'helpText', 'selectionMarker', 'checkedIndices', 'markableCount']) {
    if (options[key] !== undefined) fields[key] = options[key];
  }
  return fields;
}

// The caller owns the one authoritative pending map; this module only installs
// capture and the shared synchronous native/human/Manager settlement boundary.
export function installNativeDecisions({ pending, identity, emit, opportunity, nativeAnswer, srs, authorizeMedia }) {
  const origins = new AsyncLocalStorage();
  const patches = new Set();
  let disposed = false;
  function cancellation(method) {
    return method === 'approve' || method === 'confirm' ? nativeAnswer({ method }, false) : undefined;
  }
  function sameSession(request) {
    const current = identity();
    return request.instanceId === current.instanceId && request.generation === current.generation &&
      request.sessionId === current.sessionId && request.workspaceEpoch === current.workspaceEpoch;
  }
  function captureIdentity() {
    const current = identity();
    const origin = origins.getStore();
    if (origin && (origin.sessionId !== current.sessionId || origin.workspaceEpoch !== current.workspaceEpoch)) throw new Error('stale_generation');
    return immutable({ ...current, createdAt: Date.now(), agentOrigin: origin?.agentOrigin ?? { kind: 'unattributed', id: null, name: null } });
  }
  const installed = ui => !!ui && patches.has(Object.getOwnPropertyDescriptor(ui, PATCH)?.value);
  async function settleMapped({ hooks, request, requestId, options, localAbort, form }, source, value, error) {
    try {
      const reason = retirementReason(source, options, value, error);
      if (reason) {
        await hooks.retired(requestId, reason);
        return { answer: reason === 'timeout' ? undefined : value, problem: error };
      }
      if (!['human', 'native'].includes(source)) throw new Error('human_only_decision');
      if (!sameSession(request)) throw new Error('stale_generation');
      const answer = form ? form.answer(value) : nativeAnswer(request, value);
      const provenance = source === 'human' ? 'human' : 'nativeHuman';
      const receipt = form ? await hooks.receiptForm(requestId, provenance, answer) : await hooks.receipt(requestId, provenance, answer.results);
      if (typeof receipt?.receiptId !== 'string' || !receipt.receiptId) throw new Error('srs_answer_receipt_not_persisted');
      return { answer, problem: error };
    } catch (error_) {
      localAbort.abort();
      try { await hooks.retired(requestId, 'failed'); } catch { /* Failed persistence remains unanswered; native tool rejects. */ }
      return { answer: value, problem: error_ };
    }
  }
  function begin(ui, descriptor, { method, args, optionsIndex, options, captured, requestId, hooks, form }) {
    if (disposed || !sameSession(captured)) throw new Error('stale_generation');
    const effective = hooks ? { ...options, ompManagerHumanOnly: true, acceptImages: false } : options;
    // Undefined disables the SDK's recommendation timeout for this invocation only.
    if (hooks) delete effective.timeout;
    const request = immutable({ ...captured, requestId, method, humanOnly: effective.ompManagerHumanOnly === true, ...promptFields(method, args, effective), ...form?.fields });
    const localAbort = new AbortController();
    const nativeArgs = [...args];
    const nativeOptions = { ...effective };
    delete nativeOptions.ompManagerHumanOnly;
    nativeArgs[optionsIndex] = { ...nativeOptions, signal: options.signal ? AbortSignal.any([options.signal, localAbort.signal]) : localAbort.signal };
    return new Promise((resolve, reject) => {
      let settled = false;
      const onAbort = () => finish('native', cancellation(method));
      const finish = (source, value, error) => {
        if (settled) return false;
        // Claim synchronously, before receipt I/O or any native/Manager race.
        settled = true;
        options.signal?.removeEventListener('abort', onAbort);
        pending.delete(requestId);
        if (source !== 'native') localAbort.abort();
        const release = (answer, problem) => {
          emit('decision_resolved', { requestId, source, sessionId: request.sessionId });
          opportunity();
          if (problem) reject(problem); else resolve(answer);
        };
        if (!hooks) {
          release(value, error);
          return true;
        }
        settleMapped({ hooks, request, requestId, options, localAbort, form }, source, value, error).then(result => release(result.answer, result.problem));
        return true;
      };
      pending.set(requestId, { request, finish, answer: form?.answer, srsAnswer: form && hooks ? answer => hooks.formResponse(requestId, answer) : undefined, signal: options.signal, advisory: false });
      options.signal?.addEventListener('abort', onAbort, { once: true });
      if (options.signal?.aborted) {
        onAbort();
        return;
      }
      try {
        form?.authorize();
        emit('needs_decision', request);
        form?.authorize();
        Promise.resolve(descriptor.value.apply(ui, nativeArgs)).then(value => finish('native', value), error => finish('native', undefined, error));
      } catch (error) {
        finish('native', undefined, error);
      }
    });
  }
  function installUi(ui) {
    if (disposed || !ui) return false;
    if (installed(ui)) return [...ui[PATCH].originals.keys()].every(method => typeof ui[method] === 'function');
    const originals = new Map();
    for (const method of METHODS) {
      const descriptor = Object.getOwnPropertyDescriptor(ui, method);
      // OMSP still uses askDialog; formDialog is optional in the native extension API.
      if (method === 'formDialog' && !descriptor) continue;
      if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable) return false;
      originals.set(method, descriptor);
    }
    const patch = { ui, originals, wrappers: new Map() };
    for (const [method, descriptor] of originals) {
      const wrapper = (...args) => {
        if (disposed) return descriptor.value.apply(ui, args);
        const optionsIndex = ['approve', 'askDialog', 'formDialog', 'custom'].includes(method) ? 1 : 2;
        const options = args[optionsIndex] ?? {};
        if (options.signal?.aborted) return Promise.resolve(cancellation(method));
        let captured;
        try { captured = captureIdentity(); } catch (error) { return Promise.reject(error); }
        const requestId = crypto.randomUUID();
        const srsHooks = ['askDialog', 'formDialog'].includes(method) && ['main', 'unattributed'].includes(captured.agentOrigin.kind) ? srs?.() : null;
        const hooks = srsHooks?.active() ? srsHooks : null;
        const call = { method, args, optionsIndex, options, captured, requestId, hooks };
        // Mapping is durable before the native dialog can be answered. No timeout runs while mapping.
        if (method === 'formDialog') return prepareForm(args[0], captured, options.signal, (sources, origin) => {
          if (disposed || !sameSession(origin)) throw new Error('stale_generation');
          authorizeMedia?.(sources, origin);
        }).then(async form => {
          if (options.signal?.aborted) return undefined;
          if (hooks) await hooks.mapForm(requestId, form.fields.form);
          return begin(ui, descriptor, { ...call, form });
        });
        return hooks ? Promise.resolve(hooks.map(requestId, args[0])).then(() => begin(ui, descriptor, call)) : begin(ui, descriptor, call);
      };
      patch.wrappers.set(method, wrapper);
      Object.defineProperty(ui, method, { ...descriptor, value: wrapper });
    }
    patches.add(patch);
    Object.defineProperty(ui, PATCH, { value: patch, configurable: true });
    return true;
  }
  function contextFacade(ctx) {
    if (!ctx.hasUI || !ctx.ui) return ctx;
    const current = identity();
    const agent = ctx.agent;
    const origin = immutable({ sessionId: ctx.sessionManager.getSessionId(), workspaceEpoch: current.workspaceEpoch,
      agentOrigin: agent && typeof agent.kind === 'string' ? { kind: agent.kind, id: agent.id ?? null, name: agent.name ?? null } : { kind: 'unattributed', id: null, name: null } });
    const methods = new Map();
    const ui = new Proxy(ctx.ui, { get(target, property) {
      const value = Reflect.get(target, property, target);
      if (!METHODS.includes(property) || typeof value !== 'function') return typeof value === 'function' ? value.bind(target) : value;
      if (!methods.has(property)) methods.set(property, (...args) => origins.run(origin, () => value.apply(target, args)));
      return methods.get(property);
    } });
    return Object.create(ctx, { ui: { value: ui, enumerable: true, configurable: true } });
  }
  function revalidate() {
    for (const item of pending.values()) {
      if (!sameSession(item.request)) item.finish('retired', cancellation(item.request.method));
    }
  }
  function respond(payload) {
    const item = pending.get(payload.requestId);
    if (!item) throw new Error('decision_already_resolved');
    if (!sameSession(item.request)) { item.finish('retired', cancellation(item.request.method)); throw new Error('stale_generation'); }
    if (payload.generation !== item.request.generation || payload.sessionId !== item.request.sessionId ||
      payload.workspaceEpoch !== item.request.workspaceEpoch || (payload.instanceId !== undefined && payload.instanceId !== item.request.instanceId)) throw new Error('stale_generation');
    if (item.signal?.aborted) { item.finish('native', cancellation(item.request.method)); throw new Error('decision_already_resolved'); }
    if (item.request.humanOnly && payload.source !== 'human') throw new Error('human_only_decision');
    const response = payload.response?.srsAnswer !== undefined && item.srsAnswer && payload.source === 'human'
      ? item.srsAnswer(payload.response.srsAnswer) : payload.response;
    const answer = item.answer ? item.answer(response) : nativeAnswer(item.request, response);
    if (!item.finish(payload.source === 'human' ? 'human' : 'manager', answer)) throw new Error('decision_already_resolved');
    return { accepted: true };
  }
  return { installUi, installed, contextFacade, captureIdentity, revalidate, respond,
    dispose() {
      disposed = true;
      for (const item of pending.values()) item.finish('retired', cancellation(item.request.method));
      for (const patch of patches) {
        for (const [method, descriptor] of patch.originals) {
          if (Object.getOwnPropertyDescriptor(patch.ui, method)?.value === patch.wrappers.get(method)) Object.defineProperty(patch.ui, method, descriptor);
        }
        if (Object.getOwnPropertyDescriptor(patch.ui, PATCH)?.value === patch) delete patch.ui[PATCH];
      }
      patches.clear();
    },
  };
}
