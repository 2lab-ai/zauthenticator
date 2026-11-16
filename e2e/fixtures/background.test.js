// Service worker entry of the e2e TEST COPY of the extension (e2e/autofill.e2e.mjs copies this file
// next to manifest.json and points background.service_worker at it). Never shipped: the trust gate
// requires background.service_worker to be exactly background.js.
//
// It runs the shipped entry unchanged, so the listeners are exactly the ones background.js
// registers, and exposes the worker module's menu handler, because a click in the browser's own
// context menu cannot be automated. The shipped worker has no test hooks.
//
// frameIdFor() is test-only too: the frameId the browser's context menu would report for a frame
// (what handleMenuClick() receives as info.frameId). It reads location.href in every frame of the
// tab through chrome.scripting, which the test copy may use on its routed test origins.
import './background.js';
import { handleMenuClick } from './lib/autofill-worker.js';

// The frameId of the frame in tab `tabId` whose document is at `url` now. → number, or null
async function frameIdFor(tabId, url) {
  const results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: () => location.href });
  const hit = results.find((r) => r && r.result === url);
  return hit ? hit.frameId : null;
}

globalThis.__zauthTest = { handleMenuClick, frameIdFor };
