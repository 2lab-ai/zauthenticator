// Service worker entry: wires browser events to lib/autofill-worker.js (.prd/03-autofill.md).
// Listeners are added at the top level, synchronously, so an event that wakes the worker reaches
// them.
import {
  handleMenuClick,
  handleMessage,
  onStorageChanged,
  rebuildMenu,
  syncRegistrations,
} from './lib/autofill-worker.js';

function reconcile() {
  rebuildMenu().catch(() => {});
  syncRegistrations().catch(() => {});
}

chrome.runtime.onInstalled.addListener(reconcile);
chrome.runtime.onStartup.addListener(reconcile);

chrome.contextMenus.onClicked.addListener((info, tab) => {
  handleMenuClick(info, tab).catch(() => {});
});

// The answer is sent asynchronously: returning true keeps the channel open.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse, () => sendResponse({ code: null }));
  return true;
});

chrome.storage.onChanged.addListener(onStorageChanged);
