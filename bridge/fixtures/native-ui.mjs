import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { installNativeDecisions } from '../omp-native-ui.mjs';
import { installWorkspaceChanges } from '../omp-workspace.mjs';
import { nativeAnswer, confirmedPlanHandoff } from '../omp-manager.mjs';
import { createVisualizationGuard } from '../omp-visualization-guard.mjs';

const root = process.env.NATIVE_UI_TEST_ROOT;
const sdk = process.env.OMP_SDK_DIR;
assert.ok(root && sdk);
const fromSdk = relative => import(pathToFileURL(path.join(sdk, relative)).href);
const dirs = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-utils/dirs', sdk)).href);
dirs.setProfile('default');
for (const actual of [dirs.getAgentDir(), dirs.getConfigRootDir(), dirs.getNativesDir(), dirs.getSessionsDir()]) {
  const relative = path.relative(root, actual);
  assert.ok(relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative), `storage escaped scratch root: ${actual}`);
}
// Do not construct the CLI or AgentSession: onboarding and provider setup are
// unrelated. These are the installed runner, raw UI controller, approval gate
// and actual TUI components, with only the terminal/session host provided here.
const { ensureThemeSync } = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-tui/theme', sdk)).href);
ensureThemeSync();
const { ExtensionRunner } = await fromSdk('src/extensibility/extensions/runner.ts');
const { ExtensionUiController } = await fromSdk('src/modes/controllers/extension-ui-controller.ts');
const { requestApproval } = await fromSdk('src/tools/approval.ts');
const { SessionManager } = await fromSdk('src/session/session-manager.ts');
const { ApprovalDialogComponent } = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-tui/overlays/approval-dialog', sdk)).href);
const { AskDialogComponent } = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-tui/overlays/ask-dialog', sdk)).href);
const { Container } = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-tui', sdk)).href);
const manager = SessionManager.create(root);
const pending = new Map(), events = [], sessionListeners = new Set(), errors = [];
let workspace;
let srsHooks;
let mediaGuard;
let providerCalls = 0;
const nativeUi = installNativeDecisions({ pending, nativeAnswer, srs: () => srsHooks,
  identity: () => ({ instanceId: 'native-fixture', generation: 1, ...workspace.identity() }),
  authorizeMedia: (sources, captured) => mediaGuard?.authorizeFormMedia({ agent: { kind: 'main' }, sessionManager: manager }, captured.agentOrigin, sources),
  emit: (kind, payload) => events.push({ kind, payload }), opportunity() {} });
let handlerAction, handlerValue, handlerContext;
const extension = {
  path: path.join(root, 'offline-extension.mjs'), resolvedPath: path.join(root, 'offline-extension.mjs'),
  handlers: new Map([['agent_start', [async (_event, ctx) => { handlerContext = ctx; handlerValue = await handlerAction(ctx); }]]]),
  tools: new Map(), messageRenderers: new Map(), composerShapes: new Map(), commands: new Map(), flags: new Map(), shortcuts: new Map(),
  assistantThinkingRenderers: [], assistantTextRenderers: [], transcriptPresenters: [], linkSchemes: [], fileWriteFallbackHandlers: [], fileDeleteFallbackHandlers: [],
};
const runner = new ExtensionRunner([extension], {}, root, manager, {});
const steering = [];
const agent = { peekSteeringQueue: () => steering, prioritizeSteering() {}, state: { messages: [], pendingToolCalls: new Set() } };
const session = {
  sessionManager: manager, extensionRunner: runner, agent,
  model: undefined, settings: undefined,
  getQueuedMessages: () => ({ steering, followUp: [] }),
  subscribe(fn) { sessionListeners.add(fn); return () => sessionListeners.delete(fn); },
  prompt() { providerCalls++; throw new Error('provider call prohibited'); },
};
// This transparent host exercises the same captured init/setToolUIContext seam
// without constructing a second core Agent identity or starting terminal IO.
class Host {
  constructor() {
    this.session = session; this.sessionManager = manager;
    this.editor = { pendingImages: [], pasteInFlight: false, focused: false, getText: () => '', handleDraftEdit() {} };
    this.editorContainer = new Container(); this.editorContainer.addChild(this.editor);
    this.ui = { terminal: { rows: 40, columns: 100 }, requestRender() {}, setFocus: component => { this.focus = component; } };
    this.controller = new ExtensionUiController(this);
  }
  async init() { this.isInitialized = true; await this.controller.initHooksAndCustomTools(); }
  setToolUIContext(ui, hasUI) { assert.equal(nativeUi.installed(ui), true, 'capture must precede native forwarding'); this.toolUi = ui; this.hasUI = hasUI; }
  getToolUIContext() { return this.controller.getToolUIContext(); }
  syncComposerShape() { /* Native composer layout is outside this offline decision proof. */ }
  syncExtensionLinks() { /* No terminal link surface in this host. */ }
  closeLinkBrowser() { /* No terminal link browser in this host. */ }
  present(component) { errors.push(component); }
}
workspace = installWorkspaceChanges({ pi: { InteractiveMode: Host } }, { nativeUi, hasPendingDecisions: () => pending.size > 0, emit() {}, isLeaseCurrent: () => true });
const host = new Host();
runner.onError(error => errors.push({ text: `${error.event}: ${error.error}` }));
workspace.attachContext({ agent: { kind: 'main' }, sessionManager: manager });
const tick = () => new Promise(resolve => setImmediate(resolve));
const target = () => [...pending.values()].at(-1)?.request;
const reply = (response, source = 'human') => nativeUi.respond({ ...target(), source, response });
async function waiting(componentType) {
  // Form media includes real local/HTTP I/O; bound elapsed time, not the number of empty event-loop turns.
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (pending.size && (!componentType || host.focus instanceof componentType)) return;
    await new Promise(resolve => setTimeout(resolve, 1));
  }
  throw new Error(`native component not presented; errors=${errors.length} pending=${pending.size} ${errors.map(item => item.text ?? item.constructor?.name).join(' | ')}`);
}
async function handler(action, componentType) {
  handlerAction = action;
  const done = runner.emit({ type: 'agent_start' });
  await waiting(componentType);
  return { done };
}
function retiredOnce(id) { assert.equal(events.filter(event => event.kind === 'decision_resolved' && event.payload.requestId === id).length, 1); }
try {
  await host.init();
  assert.equal(workspace.nativeUiCapabilities().nativeDecisions, true);
  assert.equal(runner.getUIContext(), host.toolUi);
  const tool = { name: 'offline_exec', formatApprovalDetails: () => ['First exact line', 'Second exact line'] };
  // Actual native tool approval entrypoint uses runner.getUIContext directly,
  // bypassing handler facades. Its honest origin must remain unattributed.
  let done = requestApproval(runner.getUIContext(), tool, {}, { reason: 'offline fixture' });
  await waiting(ApprovalDialogComponent);
  let id = target().requestId;
  assert.equal(target().method, 'approve'); assert.equal(target().agentOrigin.kind, 'unattributed');
  assert.match(target().prompt.full, /First exact line\nSecond exact line/);
  assert.notEqual(target().prompt.full, target().prompt.compact);
  reply(true);
  assert.equal(await done, 'once');
  assert.equal(host.focus, host.editor); retiredOnce(id);

  for (const response of [false, { cancelled: true }]) {
    done = requestApproval(runner.getUIContext(), tool, {});
    await waiting(ApprovalDialogComponent); id = target().requestId;
    reply(response);
    assert.equal(await done, 'deny');
    assert.equal(host.focus, host.editor); retiredOnce(id);
  }

  // Native Escape wins, retires the card, and does not require synthesized
  // keystrokes for any remote answer. This key is native proof only.
  done = requestApproval(runner.getUIContext(), tool, {});
  await waiting(ApprovalDialogComponent); id = target().requestId;
  host.focus.handleInput('\x1b');
  assert.equal(await done, 'deny'); retiredOnce(id); assert.equal(pending.size, 0);

  // Native remembered choices remain SDK answers; remote booleans approve only this call.
  const approval = {
    full: 'Native approval choices\nExact target', compact: 'Native approval choices',
    session: 'Approve this tool for this session',
    grants: [{ scope: 'target', label: 'Approve File', alwaysLabel: 'Always Approve File' }],
  };
  for (const [inputs, expected] of [
    [[{ type: 'action', act: 'approve' }], 'once'],
    [[{ type: 'select', key: 'choices', item: 'session' }], 'session'],
    [[{ type: 'select', key: 'choices', item: 'grant0' }], { grant: 'target', always: false }],
    [[{ type: 'select', key: 'choices', item: 'remember' }, { type: 'activate', key: 'choices', item: 'grant0' }], { grant: 'target', always: true }],
  ]) {
    const running = await handler(ctx => ctx.ui.approve(approval), ApprovalDialogComponent);
    id = target().requestId;
    for (const input of inputs) host.focus.handleNativeEvent(input);
    await running.done;
    assert.deepEqual(handlerValue, expected);
    assert.equal(host.focus, host.editor); retiredOnce(id);
  }

  const questions = [{ id: 'design', header: 'Design', question: 'Which exact design?', options: [{ label: 'Simple', description: 'Minimal', preview: 'preview text' }, { label: 'Rich' }], recommended: 1 }];
  let running = await handler(async ctx => { await tick(); return ctx.ui.askDialog(questions, { acceptImages: false }); }, AskDialogComponent);
  id = target().requestId;
  assert.equal(target().method, 'askDialog'); assert.equal(target().agentOrigin.kind, 'main');
  assert.equal(target().questions[0].options[0].preview, 'preview text');
  assert.notEqual(handlerContext.ui, runner.getUIContext(), 'native runner must use its real handler proxy');
  reply({ kind: 'submit', results: [{ id: 'design', selectedOptions: [], customInput: 'Human custom answer', note: 'Human note' }] });
  await running.done;
  assert.equal(handlerValue.results[0].customInput, 'Human custom answer');
  assert.deepEqual(handlerValue.results[0].selectedOptions, []);
  assert.equal(host.focus, host.editor); retiredOnce(id);

  // Native cancellation must use the captured Ask callback, not leave the card.
  running = await handler(ctx => ctx.ui.askDialog(questions), AskDialogComponent);
  id = target().requestId; host.focus.handleInput('\x1b'); await running.done;
  assert.equal(handlerValue, undefined); assert.equal(pending.size, 0); retiredOnce(id);
  running = await handler(ctx => ctx.ui.askDialog(questions), AskDialogComponent);
  reply({ kind: 'submit', results: [{ id: 'design', selectedOptions: ['Simple'], note: 'Attached note', noteOption: 'Simple' }] });
  await running.done; assert.equal(handlerValue.results[0].noteOption, 'Simple');

  if (host.toolUi.formDialog) {
    const { HtmlFormDialog } = await import(pathToFileURL(Bun.resolveSync('@oh-my-pi/pi-tui/html-form/dialog', sdk)).href);
    const { AskTool } = await fromSdk('src/tools/ask.ts');
    const { Settings } = await fromSdk('src/config/settings.ts');
    const html = `<form><input type="hidden" name="token" value="fixed"><fieldset><legend>Architecture</legend>
      <p>Review the full context before deciding.</p><p>Design?</p>
      <label><input type="radio" name="design" value="small" checked>Simple</label>
      <label><input type="radio" name="design" value="large" disabled>Rich</label>
      <label><input type="checkbox" name="features" value="logs" checked>Logs</label>
      <label><input type="checkbox" name="features" value="metrics">Metrics</label>
      <label>Seats<input type="number" name="seats" min="1" max="5" value="2" required></label>
      <label>Region<select name="region" required><option value="eu">Europe</option><option value="us" disabled>US</option></select></label>
      <label>Explanation<textarea name="explanation">Prefilled</textarea></label>
      <svg viewBox="0 0 10 10"><title>Diagram</title><circle cx="5" cy="5" r="4"/></svg></fieldset></form>`;
    running = await handler(ctx => ctx.ui.formDialog(html), HtmlFormDialog);
    id = target().requestId;
    assert.equal(target().method, 'formDialog'); assert.equal(target().agentOrigin.kind, 'main');
    assert.equal(target().html, html);
    assert.equal(target().defaults.seats, 2);
    assert.equal(target().form.fields.find(field => field.name === 'design').options[1].disabled, true);
    assert.ok(target().form.sections.flatMap(section => section.blocks).some(block => block.displaySrc?.startsWith('data:image/svg+xml;base64,')));
    const data = { token: 'fixed', design: 'small', features: ['logs', 'metrics'], seats: 3, region: 'eu', explanation: 'Human detail' };
    for (const response of [
      { data: { ...data, token: 'forged' } }, { data: { ...data, region: 'us' } },
      { data: { ...data, seats: 6 } }, { data: { ...data, region: 'invented' } },
      { data: { ...data, features: 'logs' } }, { data, timedOut: true },
      { data, notes: [{ name: 'region', value: 'us', text: 'Not selected' }] }, { kind: 'chat' },
    ]) assert.throws(() => reply(response));
    reply({ data, notes: [{ name: 'features', value: 'metrics', text: 'Human option note' }] });
    await running.done;
    assert.deepEqual(handlerValue.data, data);
    assert.equal(handlerValue.notes[0].option, 'Metrics');
    assert.equal(host.focus, host.editor); retiredOnce(id);

    const ask = new AskTool({ hasUI: false, settings: Settings.isolated({ 'speech.enabled': false }), getPlanModeState: () => ({ enabled: true }) });
    running = await handler(ctx => ask.execute('real-form-ask', { html }, undefined, undefined, ctx), HtmlFormDialog);
    id = target().requestId;
    reply({ data });
    await running.done;
    assert.deepEqual(handlerValue.details.answers.find(answer => answer.name === 'design'), { name: 'design', question: 'Design?', answer: 'Simple' });
    assert.match(handlerValue.content[0].text, /"seats": 3/);
    retiredOnce(id);

    running = await handler(ctx => ctx.ui.formDialog(html), HtmlFormDialog);
    id = target().requestId; host.focus.handleNativeEvent({ type: 'action', act: 'submit' }); await running.done;
    assert.equal(handlerValue.data.seats, 2); assert.equal(handlerValue.data.design, 'small'); retiredOnce(id);
    running = await handler(ctx => ctx.ui.formDialog(html), HtmlFormDialog);
    id = target().requestId; reply({ cancelled: true }); await running.done;
    assert.equal(handlerValue, undefined); assert.equal(pending.size, 0); retiredOnce(id);
    running = await handler(ctx => ctx.ui.formDialog(html), HtmlFormDialog);
    id = target().requestId; host.focus.handleNativeEvent({ type: 'action', act: 'cancel' }); await running.done;
    assert.equal(handlerValue, undefined); retiredOnce(id);
    running = await handler(ctx => ctx.ui.formDialog(html, { timeout: 20 }), HtmlFormDialog);
    id = target().requestId; await running.done;
    assert.equal(handlerValue.timedOut, true); retiredOnce(id);

    running = await handler(ctx => ctx.ui.input('Credential', '', { secret: true }));
    assert.equal(target().secret, true);
    host.focus.handleInput('private-input');
    assert.equal(host.focus.render(100).join('\n').includes('private-input'), false);
    reply('private-input'); await running.done; assert.equal(handlerValue, 'private-input');

    const abortForm = new AbortController();
    running = await handler(ctx => ctx.ui.formDialog(html, { signal: abortForm.signal }), HtmlFormDialog);
    id = target().requestId; abortForm.abort(); await running.done;
    assert.equal(handlerValue, undefined); retiredOnce(id); assert.equal(host.focus, host.editor);
    assert.equal(await runner.getUIContext().formDialog(html, { signal: abortForm.signal }), undefined);
    assert.equal(pending.size, 0);

    const duplicateHtml = `<form><p>Choose</p><label><input type="checkbox" name="choice" value="same">First</label>
      <label><input type="checkbox" name="choice" value="same">Second</label></form>`;
    running = await handler(ctx => ctx.ui.formDialog(duplicateHtml), HtmlFormDialog);
    assert.throws(() => reply({ data: { choice: ['same', 'same'] }, notes: [{ name: 'choice', value: 'same', text: 'ambiguous' }] }), /note/);
    reply({ data: { choice: ['same', 'same'] }, notes: [{ name: 'choice', option: 'First', value: 'same', text: 'One' }, { name: 'choice', option: 'Second', value: 'same', text: 'Two' }] });
    await running.done; assert.deepEqual(handlerValue.notes.map(note => note.option), ['First', 'Second']);

    const receipts = [], retired = [];
    const persisted = Promise.withResolvers();
    srsHooks = { active: () => true, mapForm: async (_id, form) => assert.equal(form.fields[0].question, 'Choose'),
      receiptForm: async (_id, source, answer) => { receipts.push({ source, answer }); await persisted.promise; return { receiptId: 'persisted' }; },
      retired: async (_id, reason) => retired.push(reason) };
    const srsHtml = duplicateHtml.replaceAll('value="same"', 'value="first"').replace('value="first">Second', 'value="second">Second');
    running = await handler(ctx => ctx.ui.formDialog(srsHtml, { timeout: 1 }), HtmlFormDialog);
    id = target().requestId;
    assert.equal(target().humanOnly, true); assert.equal(target().timeout, undefined);
    assert.throws(() => reply({ data: { choice: ['first'] } }, 'manager'), /human_only_decision/);
    host.focus.handleNativeEvent({ type: 'action', act: 'submit' });
    await tick();
    assert.equal(pending.size, 0); assert.equal(receipts[0].source, 'nativeHuman');
    persisted.resolve(); await running.done; retiredOnce(id);
    assert.deepEqual(handlerValue.data, { choice: [] }); assert.deepEqual(retired, []);
    srsHooks = undefined;

    const hiddenHtml = '<form><input type="hidden" name="enabled" value="no"><label><input type="checkbox" name="enabled" value="yes">Enabled</label></form>';
    running = await handler(ctx => ctx.ui.formDialog(hiddenHtml), HtmlFormDialog);
    assert.deepEqual(host.focus.data(), { enabled: 'no' });
    host.focus.handleNativeEvent({ type: 'action', act: 'submit' }); await running.done;
    assert.deepEqual(handlerValue.data, { enabled: 'no' });
    for (const enabled of ['no', 'yes']) {
      running = await handler(ctx => ask.execute('hidden-form-ask', { html: hiddenHtml }, undefined, undefined, ctx), HtmlFormDialog);
      reply({ data: { enabled } }); await running.done;
      assert.match(handlerValue.content[0].text, new RegExp(`"enabled": "${enabled}"`));
      assert.equal(handlerValue.details.answers[0].answer, enabled === 'yes' ? 'Enabled' : 'no');
    }
    running = await handler(ctx => ctx.ui.formDialog(hiddenHtml.replace('type="checkbox"', 'type="checkbox" required')), HtmlFormDialog);
    assert.throws(() => reply({ data: { enabled: 'no' } }), /option|Required/);
    reply({ data: { enabled: 'yes' } }); await running.done;

    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>';
    const localImage = path.join(root, 'guarded-form.svg');
    await Bun.write(localImage, svg);
    let fetched = 0, fileReads = 0, nativeForms = 0, mapped = 0;
    const server = Bun.serve({ port: 0, fetch() { fetched++; return new Response(svg, { headers: { 'content-type': 'image/svg+xml' } }); } });
    const originalFile = Bun.file, originalForm = host.controller.showFormDialog;
    Bun.file = function (name, ...args) { if (String(name) === localImage) fileReads++; return originalFile.call(this, name, ...args); };
    host.controller.showFormDialog = function (...args) { nativeForms++; return originalForm.apply(this, args); };
    const guardContext = { agent: { kind: 'main' }, sessionManager: manager };
    const stage = { jobId: 'media-job', attemptId: 'media-attempt', stageId: 'media-stage', nonce: 'media-nonce', phase: 'specify', message: 'Ask safely' };
    const formWith = media => `<form><label>Answer<input name="answer"></label>${media}</form>`;
    try {
      const externalSvg = `<svg><image href="${server.url}secret"/></svg>`;
      const blocked = [
        `<img src="${server.url}secret">`, `<img src="${localImage}">`, `<img src="${pathToFileURL(localImage)}">`,
        externalSvg, `<img src="data:image/png;base64,${Buffer.from(externalSvg).toString('base64')}">`,
        `<svg xmlns:q="http://www.w3.org/1999/xlink"><image q:href="${server.url}secret"/></svg>`,
        `<svg xml:base="${server.url}secret"><use href="#shape"/></svg>`,
        `<svg><style>@import "${server.url}secret";</style></svg>`,
        `<svg><rect style="fill:u\\72l(${server.url}secret)"/></svg>`,
      ];
      for (const mode of ['visualization', 'srs']) {
        mediaGuard = createVisualizationGuard();
        const admission = mode === 'srs' ? mediaGuard.admitSrs(guardContext, stage)
          : mediaGuard.admit(guardContext, { requestId: 'media-request', kind: 'systemOverview', message: 'Ask safely' });
        mediaGuard.beforeAgentStart({ prompt: admission.text }, guardContext);
        if (mode === 'srs') srsHooks = { active: () => true, mapForm: async () => { mapped++; }, retired: async () => {} };
        for (const media of blocked) {
          await assert.rejects(ask.execute('blocked-media', { html: formWith(media) }, undefined, undefined,
            { hasUI: true, ui: runner.getUIContext(), abort() { throw new Error('unexpected abort'); } }), /media refused/);
        }
        assert.equal(fetched, 0); assert.equal(fileReads, 0); assert.equal(nativeForms, 0); assert.equal(mapped, 0);
        assert.equal(pending.size, 0); assert.equal(host.focus, host.editor);
        if (mode === 'srs') {
          srsHooks.mapForm = async () => { mapped++; mediaGuard.pauseSrs(guardContext, stage); };
          await assert.rejects(runner.getUIContext().formDialog(formWith(svg)), /uncertain or paused/);
          assert.equal(mapped, 1); assert.equal(nativeForms, 0); assert.equal(pending.size, 0);
        } else {
          running = await handler(ctx => ctx.ui.formDialog(formWith(svg)), HtmlFormDialog);
          reply({ data: { answer: 'inline drawing stays available' } }); await running.done;
          assert.equal(nativeForms, 1); nativeForms = 0;
        }
        srsHooks = undefined; mediaGuard.release();
      }
      mediaGuard = undefined;
      running = await handler(ctx => ctx.ui.formDialog(formWith(`<img src="${server.url}ordinary"><img src="${localImage}">`)), HtmlFormDialog);
      assert.ok(fetched > 0); assert.ok(fileReads > 0); assert.equal(nativeForms, 1);
      assert.ok(target().form.sections.flatMap(section => section.blocks).filter(block => block.kind === 'image').every(block => block.displaySrc?.startsWith('data:image/svg+xml;base64,')));
      reply({ data: { answer: 'ordinary media stays available' } }); await running.done;
    } finally {
      Bun.file = originalFile; host.controller.showFormDialog = originalForm;
      srsHooks = undefined; mediaGuard = undefined; await server.stop(true);
    }
  }

  // The owning Manager must not bypass plan handoff's explicit human boundary.
  let handoffs = 0;
  const handoff = ctx => confirmedPlanHandoff(async action => {
    if (action === 'plan_handoff_info') return { name: 'Worker', revision: 'r', needsStart: false };
    handoffs++; return { accepted: true };
  }, ctx, { summary: 'Review native-only permission boundary' });
  running = await handler(handoff);
  id = target().requestId;
  assert.equal(target().humanOnly, true);
  assert.throws(() => reply(true, 'manager'), /human_only_decision/);
  assert.equal(handoffs, 0);
  reply(true, 'human'); await running.done;
  assert.equal(handoffs, 1); assert.equal(host.focus, host.editor); retiredOnce(id);
  for (const response of [false, { cancelled: true }]) {
    running = await handler(handoff);
    id = target().requestId;
    reply(response); await running.done;
    assert.deepEqual(handlerValue, { accepted: false, cancelled: true });
    assert.equal(handoffs, 1); assert.equal(host.focus, host.editor); retiredOnce(id);
  }

  const aborted = new AbortController();
  done = runner.getUIContext().approve(approval, { signal: aborted.signal });
  await waiting(ApprovalDialogComponent); id = target().requestId;
  aborted.abort();
  assert.equal(await done, 'deny'); retiredOnce(id); assert.equal(host.focus, host.editor);

  // Native timeout and native queued steering remain denials, not approvals.
  let timedOut = false;
  done = runner.getUIContext().approve({ full: 'Timeout approval', compact: 'Timeout approval' }, { timeout: 10, onTimeout: () => { timedOut = true; } });
  await waiting(ApprovalDialogComponent); id = target().requestId;
  assert.equal(await done, 'deny'); assert.equal(timedOut, true); retiredOnce(id);
  done = requestApproval(runner.getUIContext(), tool, {});
  await waiting(ApprovalDialogComponent); id = target().requestId;
  steering.push({ role: 'user', content: 'Stop; human steering wins' });
  for (const listener of sessionListeners) listener({ type: 'queue_update', steering });
  assert.equal(await done, 'deny'); retiredOnce(id);
  assert.equal(host.focus, host.editor);
  assert.equal(pending.size, 0);

  // An ordinary headless child uses native no-op UI; patching the main
  // runner's prototype must not invent a request in that independent runner.
  const child = new ExtensionRunner([], {}, root, manager, {}, undefined, undefined, undefined, undefined,
    { kind: 'sub', id: 'headless', name: 'task', depth: 1 });
  child.initialize({}, {}, undefined, undefined, 'print');
  assert.equal(child.hasUI(), false);
  assert.equal(await child.createContext().ui.confirm('Headless', 'No dialog'), false);
  child.clearManagedTimers(); child.disposeFileFallbacks();
  assert.equal(pending.size, 0); assert.equal(providerCalls, 0); assert.equal(errors.length, 0);
  console.log('Native raw UI and handler component settlement verified');
} finally {
  nativeUi.dispose(); await workspace.dispose();
  runner.clearManagedTimers(); runner.disposeFileFallbacks();
  await manager.close();
}
