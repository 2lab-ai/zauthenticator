// The only code in the extension that opens a tab. Every destination is this extension's own
// popup page with one of the fixed view names below; nothing else can be passed in.
// The trust gate pins this file by sha256 and rejects tab/window-opening calls anywhere else.

const VIEWS = new Set(['add-file', 'settings']);

/** Opens popup/popup.html#<view> of this extension in a new tab. */
export async function openOwnView(view) {
  if (!VIEWS.has(view)) throw new Error(`Unknown view: ${view}`);
  await chrome.tabs.create({ url: chrome.runtime.getURL(`popup/popup.html#${view}`) });
}
