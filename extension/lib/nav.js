// The only code in the extension that opens a tab or a window. Every destination is this
// extension's own popup page with one of the fixed view names below; nothing else can be passed in.
// The trust gate pins this file by sha256 and rejects tab/window-opening calls anywhere else.

const TAB_VIEWS = new Set(['add-file', 'settings']);
const WINDOW_VIEWS = new Set(['bind', 'unlock']);

/** Opens popup/popup.html#<view> of this extension in a new tab. */
export async function openOwnView(view) {
  if (!TAB_VIEWS.has(view)) throw new Error(`Unknown view: ${view}`);
  await chrome.tabs.create({ url: chrome.runtime.getURL(`popup/popup.html#${view}`) });
}

/** Opens popup/popup.html#<view> of this extension in a small popup window. */
export async function openOwnWindow(view) {
  if (!WINDOW_VIEWS.has(view)) throw new Error(`Unknown view: ${view}`);
  await chrome.windows.create({
    url: chrome.runtime.getURL(`popup/popup.html#${view}`),
    type: 'popup',
    width: 400,
    height: 600,
  });
}
