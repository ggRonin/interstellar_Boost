// Заглушки браузера для instrumentation-скрипта Cap.js: скрипт исполняется в vm-контексте,
// который снаружи выглядит как sandbox-iframe Chrome/Windows (srcdoc).
//
// Что скрипт проверяет и как мы это закрываем:
//  - стек ошибок без node:internal / file:/// / [eval]: код идёт под именем about:srcdoc, onload
//    вызывается из микрозадачи контекста — в стеке нет ни одного кадра Node;
//  - глобальные имена без process/require/Buffer: в контекст кладём только имена, которые есть в Chrome;
//  - instanceof Window/Document/Navigator/HTMLElement/EventTarget и [object Window] и т.п.;
//  - «родной» код у getParameter/toDataURL/getImageData/permissions.query: это bound-функции,
//    их toString в V8 — «function () { [native code] }»;
//  - вычисляемые значения (state) строятся на DOM: appendChild/removeChild/children/innerText
//    повторяют семантику браузера.
'use strict';
const vm = require('vm');

// Ширина строки-образца при 72px (Chromium, Windows): неизвестный шрифт = шрифт по умолчанию (Times New Roman)
const FONT_WIDTHS = {
  'sans-serif': 1200.88, 'serif': 1156.97, 'monospace': 989.66, 'Arial': 1200.88,
  "'Times New Roman'": 1156.97, "'Courier New'": 1080.19, "'Segoe UI'": 1213.5,
  'Tahoma': 1203.86, 'Calibri': 1122.47,
};
const DEFAULT_FONT_WIDTH = 1156.97;

const DEFAULT_ENV = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  brands: [['Google Chrome', '131'], ['Chromium', '131'], ['Not_A Brand', '24']],
  platform: 'Win32',
  uaPlatform: 'Windows',
  language: 'en-US',
  languages: ['en-US', 'en'],
  hardwareConcurrency: 8,
  deviceMemory: 8,
  screen: [1920, 1080],
  avail: [1920, 1032],
  outer: [1920, 1032],
  inner: [1920, 945],
  webglVendor: 'WebKit',
  webglRenderer: 'WebKit WebGL',
};

// Исполняется внутри контекста. Ничего лишнего в глобальную область не оставляет:
// всё внутреннее живёт в замыкании, наружу — только имена, которые есть в Chrome.
const PRELUDE = String.raw`(function (E, sink, timers, fontWidths, defaultFontWidth) {
  const G = globalThis;
  const S = new WeakMap();            // внутреннее состояние объектов
  const st = o => S.get(o);
  const illegal = () => { throw new TypeError('Illegal constructor'); };
  const def = (o, k, v) => Object.defineProperty(o, k, { value: v, writable: true, configurable: true, enumerable: false });
  const getter = (proto, k, fn) => Object.defineProperty(proto, k, { get: fn, configurable: true, enumerable: true });
  const tag = (C, name) => Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true });
  const native = fn => fn.bind(null);   // toString bound-функции — «[native code]»

  class EventTarget {
    constructor() { S.set(this, { listeners: {} }); }
    addEventListener(type, fn) {
      const s = st(this); if (!s || typeof fn !== 'function') return;
      (s.listeners[type] ||= []).includes(fn) || s.listeners[type].push(fn);
    }
    removeEventListener(type, fn) {
      const s = st(this); if (!s || !s.listeners[type]) return;
      s.listeners[type] = s.listeners[type].filter(f => f !== fn);
    }
    dispatchEvent(ev) {
      const s = st(this); if (!s) return true;
      for (const fn of (s.listeners[ev.type] || []).slice()) fn.call(this, ev);
      return true;
    }
  }
  class Event {
    constructor(type, init) { def(this, '_t', String(type)); this.bubbles = !!(init && init.bubbles); }
    get type() { return this._t; }
  }
  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); def(this, '_d', init && 'detail' in init ? init.detail : null); }
    get detail() { return this._d; }
  }

  class Node extends EventTarget {
    constructor() { super(); Object.assign(st(this), { kids: [], parent: null }); }
    get parentNode() { return st(this).parent; }
    get parentElement() { const p = st(this).parent; return p instanceof Element ? p : null; }
    get childNodes() { return st(this).kids.slice(); }
    get firstChild() { return st(this).kids[0] || null; }
    get lastChild() { const k = st(this).kids; return k[k.length - 1] || null; }
    appendChild(child) {
      const old = st(child).parent;
      if (old) old.removeChild(child);
      st(this).kids.push(child);
      st(child).parent = this;
      return child;
    }
    removeChild(child) {
      const k = st(this).kids, i = k.indexOf(child);
      if (i < 0) throw new Error("Failed to execute 'removeChild' on 'Node': The node to be removed is not a child of this node.");
      k.splice(i, 1);
      st(child).parent = null;
      return child;
    }
    get textContent() { return st(this).kids.map(n => n.textContent).join(''); }
    set textContent(v) {
      for (const n of st(this).kids) st(n).parent = null;
      st(this).kids = [];
      const s = v == null ? '' : String(v);
      if (s) this.appendChild(new Text(s));
    }
  }
  class Text extends Node {
    constructor(data) { super(); st(this).data = String(data); }
    get textContent() { return st(this).data; }
    set textContent(v) { st(this).data = String(v); }
    get data() { return st(this).data; }
  }
  class Element extends Node {
    get tagName() { return st(this).tag; }
    get nodeName() { return st(this).tag; }
    get children() { return st(this).kids.filter(n => n instanceof Element); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    // элементы скрытые (display:none) или вне отрисовки — innerText = textContent
    get innerText() { return this.textContent; }
    set innerText(v) { this.textContent = v; }
    setAttribute(k, v) { st(this).attrs[k] = String(v); }
    getAttribute(k) { return k in st(this).attrs ? st(this).attrs[k] : null; }
    removeAttribute(k) { delete st(this).attrs[k]; }
    hasAttribute(k) { return k in st(this).attrs; }
    getAttributeNames() { return Object.keys(st(this).attrs); }
    hasAttributes() { return Object.keys(st(this).attrs).length > 0; }
    get attributes() { return Object.entries(st(this).attrs).map(([name, value]) => ({ name, value })); }
    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }
    contains(n) { for (let x = n; x; x = st(x).parent) if (x === this) return true; return false; }
    getElementsByTagName(t) {
      t = String(t).toUpperCase();
      const out = [];
      const walk = (e) => { for (const c of e.children) { if (t === '*' || st(c).tag === t) out.push(c); walk(c); } };
      walk(this);
      return out;
    }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    remove() { const p = st(this).parent; if (p) p.removeChild(this); }
    getBoundingClientRect() {
      let w = 0, h = 0;
      if (st(this).tag === 'SPAN' && this.textContent) {
        const fam = String(this.style.fontFamily || '').trim();
        w = fam in fontWidths ? fontWidths[fam] : defaultFontWidth;
        h = 83;
      }
      return { x: 0, y: 0, left: 0, top: 0, width: w, height: h, right: w, bottom: h };
    }
  }
  class HTMLElement extends Element {}
  class HTMLDivElement extends HTMLElement {}
  class HTMLSpanElement extends HTMLElement {}
  class HTMLBodyElement extends HTMLElement {}
  class HTMLHeadElement extends HTMLElement {}
  class HTMLHtmlElement extends HTMLElement {}
  class HTMLScriptElement extends HTMLElement {}
  class HTMLIFrameElement extends HTMLElement {}
  class HTMLUnknownElement extends HTMLElement {}

  class WebGLRenderingContext {
    get canvas() { return st(this).canvas; }
  }
  const GL = { VENDOR: 0x1F00, RENDERER: 0x1F01, VERSION: 0x1F02 };
  for (const [k, v] of Object.entries(GL)) {
    Object.defineProperty(WebGLRenderingContext, k, { value: v, enumerable: true });
    Object.defineProperty(WebGLRenderingContext.prototype, k, { value: v, enumerable: true });
  }
  def(WebGLRenderingContext.prototype, 'getParameter', native(function getParameter(p) {
    if (p === GL.VENDOR) return E.webglVendor;
    if (p === GL.RENDERER) return E.webglRenderer;
    if (p === GL.VERSION) return 'WebGL 1.0 (OpenGL ES 2.0 Chromium)';
    return null;
  }));
  def(WebGLRenderingContext.prototype, 'getExtension', native(function getExtension() { return null; }));
  def(WebGLRenderingContext.prototype, 'getSupportedExtensions', native(function getSupportedExtensions() { return []; }));
  class CanvasRenderingContext2D {}
  def(CanvasRenderingContext2D.prototype, 'getImageData', native(function getImageData() { return { data: new Uint8ClampedArray(4) }; }));
  def(CanvasRenderingContext2D.prototype, 'fillText', native(function fillText() {}));
  def(CanvasRenderingContext2D.prototype, 'fillRect', native(function fillRect() {}));
  def(CanvasRenderingContext2D.prototype, 'measureText', native(function measureText() { return { width: 0 }; }));
  class HTMLCanvasElement extends HTMLElement {}
  def(HTMLCanvasElement.prototype, 'getContext', native(function getContext() { return null; }));
  def(HTMLCanvasElement.prototype, 'toDataURL', native(function toDataURL() { return 'data:,'; }));

  const TAGS = { DIV: HTMLDivElement, SPAN: HTMLSpanElement, CANVAS: HTMLCanvasElement, BODY: HTMLBodyElement,
                 HEAD: HTMLHeadElement, HTML: HTMLHtmlElement, SCRIPT: HTMLScriptElement, IFRAME: HTMLIFrameElement };
  function make(tagName) {
    const T = String(tagName).toUpperCase();
    const el = new (TAGS[T] || HTMLUnknownElement)();
    Object.assign(st(el), { tag: T, attrs: {} });
    def(el, 'style', {});
    if (T === 'CANVAS') {
      // getContext на прототипе — «родной»; для конкретного холста отдаём контекст по типу
      const ctxs = {};
      Object.defineProperty(el, 'getContext', { value: native(function getContext(kind) {
        kind = String(kind);
        if (/^(experimental-)?webgl$/.test(kind)) {
          if (!ctxs.gl) { ctxs.gl = Object.create(WebGLRenderingContext.prototype); S.set(ctxs.gl, { canvas: el }); }
          return ctxs.gl;
        }
        if (kind === '2d') return ctxs.c2d ||= Object.create(CanvasRenderingContext2D.prototype);
        return null;
      }), configurable: true, writable: true, enumerable: false });
      el.width = 300; el.height = 150;
    }
    return el;
  }

  class Document extends Node {
    get defaultView() { return G; }
    get body() { return st(this).body; }
    get head() { return st(this).head; }
    get documentElement() { return st(this).html; }
    get readyState() { return 'complete'; }
    get hidden() { return false; }
    get visibilityState() { return 'visible'; }
    get URL() { return 'about:srcdoc'; }
    get referrer() { return ''; }
    get characterSet() { return 'UTF-8'; }
    get compatMode() { return 'CSS1Compat'; }
    get contentType() { return 'text/html'; }
    hasFocus() { return false; }   // невидимый iframe фокуса не имеет
    get cookie() { return ''; }
    set cookie(v) {}
    createElement(t) { return make(t); }
    createTextNode(t) { return new Text(t); }
    getElementsByTagName(t) { t = String(t).toUpperCase(); return t === 'BODY' ? [this.body] : t === 'HEAD' ? [this.head] : []; }
    querySelector() { return null; }
    querySelectorAll() { return []; }
  }

  class MimeType {}
  class MimeTypeArray {}
  class Plugin {}
  class PluginArray {}
  class Navigator {}
  class Screen {}
  class Permissions {}
  class NavigatorUAData {}
  class Window extends EventTarget {}
  for (const [C, n] of [[EventTarget, 'EventTarget'], [Event, 'Event'], [CustomEvent, 'CustomEvent'], [Node, 'Node'],
      [Text, 'Text'], [Element, 'Element'], [HTMLElement, 'HTMLElement'], [HTMLDivElement, 'HTMLDivElement'],
      [HTMLSpanElement, 'HTMLSpanElement'], [HTMLBodyElement, 'HTMLBodyElement'], [HTMLHeadElement, 'HTMLHeadElement'],
      [HTMLHtmlElement, 'HTMLHtmlElement'], [HTMLScriptElement, 'HTMLScriptElement'], [HTMLIFrameElement, 'HTMLIFrameElement'],
      [HTMLUnknownElement, 'HTMLUnknownElement'], [HTMLCanvasElement, 'HTMLCanvasElement'],
      [WebGLRenderingContext, 'WebGLRenderingContext'], [CanvasRenderingContext2D, 'CanvasRenderingContext2D'],
      [Document, 'HTMLDocument'], [MimeType, 'MimeType'], [MimeTypeArray, 'MimeTypeArray'], [Plugin, 'Plugin'],
      [PluginArray, 'PluginArray'], [Navigator, 'Navigator'], [Screen, 'Screen'], [Permissions, 'Permissions'],
      [NavigatorUAData, 'NavigatorUAData'], [Window, 'Window']]) tag(C, n);

  // ── plugins / mimeTypes (как у Chrome со встроенным PDF) ────────────────
  function list(Proto, items, namedKey) {
    const o = Object.create(Proto.prototype);
    items.forEach((it, i) => def(o, i, it));
    Object.defineProperty(o, 'length', { get: () => items.length, enumerable: false });
    def(o, 'item', i => items[i] || null);
    def(o, 'namedItem', n => items.find(x => x[namedKey] === n) || null);
    o[Symbol.iterator] = function* () { yield* items; };
    return o;
  }
  const mt = (type, suffixes) => { const m = Object.create(MimeType.prototype);
    Object.assign(m, { type, suffixes, description: 'Portable Document Format' }); return m; };
  const mimes = [mt('application/pdf', 'pdf'), mt('text/pdf', 'pdf')];
  const pluginNames = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];
  const plugins = pluginNames.map(name => { const p = Object.create(Plugin.prototype);
    Object.assign(p, { name, filename: 'internal-pdf-viewer', description: 'Portable Document Format' }); return p; });
  const pluginArray = list(PluginArray, plugins, 'name');
  const mimeArray = list(MimeTypeArray, mimes, 'type');

  // ── navigator ───────────────────────────────────────────────────────────
  const uaData = Object.create(NavigatorUAData.prototype);
  getter(NavigatorUAData.prototype, 'brands', () => E.brands.map(([brand, version]) => ({ brand, version })));
  getter(NavigatorUAData.prototype, 'mobile', () => false);
  getter(NavigatorUAData.prototype, 'platform', () => E.uaPlatform);
  const permissions = Object.create(Permissions.prototype);
  def(Permissions.prototype, 'query', native(function query() { return Promise.resolve({ state: 'prompt' }); }));
  const navigator = Object.create(Navigator.prototype);
  const NAV = {
    userAgent: () => E.userAgent, appVersion: () => E.userAgent.replace(/^Mozilla\//, ''),
    appName: () => 'Netscape', appCodeName: () => 'Mozilla', product: () => 'Gecko', productSub: () => '20030107',
    vendor: () => 'Google Inc.', vendorSub: () => '', platform: () => E.platform,
    language: () => E.language, languages: () => E.languages.slice(), onLine: () => true, cookieEnabled: () => true,
    hardwareConcurrency: () => E.hardwareConcurrency, deviceMemory: () => E.deviceMemory, maxTouchPoints: () => 0,
    webdriver: () => false, pdfViewerEnabled: () => true, doNotTrack: () => null,
    plugins: () => pluginArray, mimeTypes: () => mimeArray, userAgentData: () => uaData, permissions: () => permissions,
  };
  for (const [k, fn] of Object.entries(NAV)) getter(Navigator.prototype, k, fn);

  const screen = Object.create(Screen.prototype);
  const SCR = { width: () => E.screen[0], height: () => E.screen[1], availWidth: () => E.avail[0],
                availHeight: () => E.avail[1], availLeft: () => 0, availTop: () => 0, colorDepth: () => 24,
                pixelDepth: () => 24, isExtended: () => false, orientation: () => ({ type: 'landscape-primary', angle: 0 }) };
  for (const [k, fn] of Object.entries(SCR)) getter(Screen.prototype, k, fn);

  // ── document ────────────────────────────────────────────────────────────
  const document = Object.create(Document.prototype);
  S.set(document, { listeners: {}, kids: [], parent: null });
  const html = make('html'), head = make('head'), body = make('body');
  html.appendChild(head); html.appendChild(body); document.appendChild(html);
  Object.assign(st(document), { html, head, body });

  // ── window ──────────────────────────────────────────────────────────────
  S.set(G, { listeners: {} });
  Object.setPrototypeOf(G, Window.prototype);
  const parent = {};
  def(parent, 'postMessage', native(function postMessage(msg) { sink(JSON.stringify(msg)); }));
  const location = { href: 'about:srcdoc', origin: 'null', protocol: 'about:', host: '', hostname: '', pathname: 'srcdoc', search: '', hash: '' };
  const enc = s => String(s);
  const own = {
    window: G, self: G, top: parent, parent, frames: G, document, navigator, screen, location, origin: 'null',
    chrome: { app: { isInstalled: false }, runtime: {} },
    devicePixelRatio: 1, outerWidth: E.outer[0], outerHeight: E.outer[1], innerWidth: E.inner[0], innerHeight: E.inner[1],
    screenX: 0, screenY: 0, scrollX: 0, scrollY: 0, isSecureContext: false, onload: null, name: '', length: 0, closed: false,
    EventTarget, Event, CustomEvent, Node, Text, Element, HTMLElement, HTMLDivElement, HTMLSpanElement, HTMLBodyElement,
    HTMLHeadElement, HTMLHtmlElement, HTMLScriptElement, HTMLIFrameElement, HTMLUnknownElement, HTMLCanvasElement,
    WebGLRenderingContext, CanvasRenderingContext2D, Document, HTMLDocument: Document, MimeType, MimeTypeArray, Plugin,
    PluginArray, Navigator, Screen, Permissions, NavigatorUAData, Window,
    setTimeout: native(timers.setTimeout), clearTimeout: native(timers.clearTimeout),
    setInterval: native(timers.setInterval), clearInterval: native(timers.clearInterval),
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    atob: native(s => timers.atob(enc(s))), btoa: native(s => timers.btoa(enc(s))),
    performance: { now: native(() => timers.now()), timeOrigin: Date.now() },
  };
  for (const [k, v] of Object.entries(own)) def(G, k, v);
  for (const C of [Navigator, Screen, Permissions, MimeType, MimeTypeArray, Plugin, PluginArray, NavigatorUAData, Window, Document]) {
    // настоящие конструкторы этих интерфейсов недоступны напрямую
    Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true });
  }
  void illegal;
})`;

/** Исполнить instrumentation-скрипт и вернуть {result} | {blocked} | {timeout}. */
function runInstrumentation(code, envOverrides = {}, timeoutMs = 20000) {
  const E = { ...DEFAULT_ENV, ...envOverrides };
  return new Promise((resolve) => {
    let done = false;
    const pending = new Set();
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(guard);
      for (const t of pending) clearTimeout(t);
      resolve(r);
    };
    const guard = setTimeout(() => finish({ timeout: true }), timeoutMs);

    const sink = (json) => {
      let msg;
      try { msg = JSON.parse(json); } catch { return; }
      if (!msg || msg.type !== 'cap:instr') {
        if (msg && msg.type === 'cap:error') finish({ timeout: true });
        return;
      }
      if (msg.blocked) return finish({ blocked: true });
      if (!msg.result) return finish({ timeout: true });
      finish({ result: { ...msg.result, vp: [E.inner[0], E.inner[1]] } });
    };
    const timers = {
      setTimeout: (fn, ms, ...a) => { const t = setTimeout(() => { pending.delete(t); if (!done) fn(...a); }, ms); pending.add(t); return pending.size; },
      clearTimeout: () => {},
      setInterval: () => 0,
      clearInterval: () => {},
      atob: (s) => Buffer.from(s, 'base64').toString('latin1'),
      btoa: (s) => Buffer.from(s, 'latin1').toString('base64'),
      now: () => performance.now(),
    };

    const ctx = vm.createContext({}, { name: 'about:srcdoc', codeGeneration: { strings: true, wasm: false } });
    const opts = { filename: 'about:srcdoc', timeout: timeoutMs };
    vm.runInContext(PRELUDE, ctx, { filename: 'about:blank' })(E, sink, timers, FONT_WIDTHS, DEFAULT_FONT_WIDTH);
    try {
      vm.runInContext(code, ctx, opts);
      // onload — из микрозадачи контекста: в стеке не будет кадров Node (vm, timers)
      vm.runInContext('Promise.resolve().then(() => { if (typeof onload === "function") onload(new Event("load")); })', ctx, opts);
    } catch (e) {
      finish({ timeout: true, error: String(e) });
    }
  });
}

module.exports = { runInstrumentation, DEFAULT_ENV };
