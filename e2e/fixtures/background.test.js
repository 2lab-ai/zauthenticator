// Service worker entry of the e2e TEST COPY of the extension (e2e/autofill.e2e.mjs copies this file
// next to manifest.json and points background.service_worker at it). Never shipped: the trust gate
// requires background.service_worker to be exactly background.js.
//
// It runs the shipped entry unchanged, so the listeners are exactly the ones background.js
// registers, and exposes the worker module's menu handler, because a click in the browser's own
// context menu cannot be automated. The shipped worker has no test hooks.
import './background.js';
import { handleMenuClick } from './lib/autofill-worker.js';

globalThis.__zauthTest = { handleMenuClick };
