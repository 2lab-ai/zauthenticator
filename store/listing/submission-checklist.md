# Store submission checklist

Step by step for publishing zauthenticator to the Chrome Web Store and Microsoft Edge Add-ons, and
for every update after that. The texts to paste are in [chrome-web-store.md](chrome-web-store.md)
and [edge-addons.md](edge-addons.md). Facts were checked on 2026-11-16 against the sources named;
**unverified** marks what the documentation does not state.

## 0. Before the first submission

- [ ] The docs, icon, popup and auto-fill changes for 0.2.0 are merged to `main`.
- [ ] `PRIVACY.md` is on `main`, so
      `https://github.com/2lab-ai/zauthenticator/blob/main/PRIVACY.md` opens. Both stores need this
      URL at submission time.
- [ ] The release `v0.2.0` exists on GitHub with `zauthenticator-0.2.0.zip` and its sha256
      (pushing the tag `v0.2.0` runs the release workflow). Download the zip and check it:
      `shasum -a 256 zauthenticator-0.2.0.zip` must print the sha256 in the release notes.
- [ ] The store images exist at the paths below and have the right sizes. On macOS:
      `sips -g pixelWidth -g pixelHeight store/assets/*.png store/assets/screenshots/*.png`

| File | Expected size | Used by |
|---|---|---|
| `store/assets/chrome-icon-128.png` | 128×128 | Chrome Web Store icon |
| `store/assets/edge-logo-300.png` | 300×300 (1:1, at least 128×128) | Edge extension logo |
| `store/assets/promo-small-440x280.png` | 440×280 | both stores, small tile |
| `store/assets/promo-marquee-1400x560.png` | 1400×560 | both stores, marquee / large tile |
| `store/assets/screenshots/1-codes.png` | 1280×800 | both stores |
| `store/assets/screenshots/2-autofill.png` | 1280×800 | both stores |
| `store/assets/screenshots/3-bind.png` | 1280×800 | both stores |
| `store/assets/screenshots/4-add.png` | 1280×800 | both stores |
| `store/assets/screenshots/5-settings.png` | 1280×800 | both stores |

Quoted labels checked against `extension/_locales/en/messages.json` on 2026-11-17 (v0.2.0).

## 1. Accounts (once)

**Chrome Web Store developer account**

- [ ] Open the Chrome Web Store Developer Dashboard, accept the developer agreement and policies,
      and pay the **one-time** registration fee. The amount is not stated in the docs
      (**unverified**; the dashboard shows it).
      source: https://developer.chrome.com/docs/webstore/register, checked 2026-11-16
- [ ] Choose the developer email carefully: it cannot be changed after the account is created.
      source: https://developer.chrome.com/docs/webstore/register, checked 2026-11-16
- [ ] Set the **publisher name** (required) and verify the **contact email** (required for new
      accounts) in the account settings. A physical address is needed only for items that sell
      something, which this one does not.
      source: https://developer.chrome.com/docs/webstore/set-up-account, checked 2026-11-16
- [ ] Public listings show a "Trader" or "Non-trader" status, so expect the dashboard to ask for
      that declaration. Where it asks and what it requires is not in the docs (**unverified**);
      answer what is true for the publisher.

**Microsoft Partner Center (Edge program) developer account**

- [ ] Sign in to Partner Center with a personal Microsoft account (MSA), or with a GitHub account,
      which creates an MSA. Work or school accounts are not supported for registration.
- [ ] In the Edge developer registration form choose the country/region and the account type
      (**Individual** or **Company**). Both are fixed after enrollment. Individual verification is
      shorter; company verification can take days to weeks.
- [ ] Enter the publisher display name (at most 50 characters) and contact info, accept the App
      Developer Agreement, click **Finish**, and wait for the verification email.
- [ ] There is **no registration fee** for the Edge program.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/create-dev-account, checked 2026-11-16

## 2. Chrome Web Store: first submission

1. [ ] Developer Dashboard → **Add new item** → choose `zauthenticator-0.2.0.zip` → **Upload**.
2. [ ] **Store listing** tab: detailed description (en, then a Korean listing), category, store
       icon, screenshots, promo tiles, homepage and support URLs. See
       [chrome-web-store.md](chrome-web-store.md#store-listing-tab).
3. [ ] **Privacy** tab: single purpose, the five permission justifications, remote code = No, data
       usage ticks and the three certifications, privacy policy URL. See
       [chrome-web-store.md](chrome-web-store.md#privacy-practices-tab).
4. [ ] **Distribution** tab: Public, all regions.
5. [ ] **Test instructions** tab: paste the certification notes from
       [edge-addons.md](edge-addons.md#notes-for-certification).
6. [ ] **Submit for review.** In the confirmation dialog you may untick automatic publishing; then
       you have up to 30 days after approval to publish before the submission returns to draft.
source: https://developer.chrome.com/docs/webstore/publish, checked 2026-11-16

**Review time:** "For most extensions, review is completed within a few days, but it can take up
to a few weeks." Contact developer support if it is pending for more than three weeks. New
developers, new extensions and broad host permissions or sensitive execution permissions
(`scripting` with `https://*/*`, even though optional) can mean a closer and longer review.
source: https://developer.chrome.com/docs/webstore/review-process, checked 2026-11-16

## 3. Edge Add-ons: first submission

1. [ ] Partner Center → Edge → **Create new extension** → drop `zauthenticator-0.2.0.zip` on
       "Drag your package here (.zip)" → **Continue**.
2. [ ] **Availability**: Public, all markets → **Save & Continue**.
3. [ ] **Properties**: category, website, support contact, mature content off → **Save & Continue**.
4. [ ] **Privacy**: same answers as the Chrome Web Store → **Save & Continue**.
5. [ ] **Store listings**: for **English** and **Korean**, the description, the logo
       (`edge-logo-300.png`, duplicate it to the other language), tiles, screenshots and search
       terms → **Save draft**. Both rows must say **Complete**.
6. [ ] **Publish** → paste the **Notes for certification** → **Publish**.
See [edge-addons.md](edge-addons.md) for every value.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

**Review time:** certification "can take up to seven business days". After it passes, the
extension is published and its status becomes **In the Store**.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

## 4. After both are live

- [ ] Replace the two "coming soon" lines in `README.md` (English and Korean sections) with the
      listing URLs: the Chrome Web Store item URL from the dashboard, and the Edge listing URL
      shown on the extension's **Overview** page in Partner Center.
- [ ] Install each store version once in a clean profile: create a passphrase, add the test
      account, fill a code from the right-click menu, allow a site and see it filled on reload.

## Before each update

1. [ ] Bump `version` in `extension/manifest.json` (each upload must have a larger version than
       the last one).
       source: https://developer.chrome.com/docs/webstore/prepare, checked 2026-11-16
2. [ ] Merge to `main`, then push the tag `v<version>`. The release workflow checks the tag
       against the manifest, runs the full CI, and publishes `zauthenticator-<version>.zip` with
       its sha256.
3. [ ] Download that zip from the release and check its sha256. Upload **the same file** to both
       stores:
       - Chrome Web Store: the item → **Package** tab → **Upload New Package**; update the Store
         listing, Privacy practices and Distribution tabs if they changed; **Submit for Review**.
         Updates are reviewed again.
         source: https://developer.chrome.com/docs/webstore/update, checked 2026-11-16
       - Partner Center: select the extension, upload the new package (the **Packages** page has
         the same drop zone as the first upload), update the metadata if it changed, then
         **Publish**. Certification of an update "can take up to 7 business days"; the update is
         live when the status shows **In the store**.
         source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/update/update-extension, checked 2026-11-16
         source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16
4. [ ] If the features, permissions or data handling changed: update `PRIVACY.md` (and its
       effective date), the texts in `store/listing/`, the summaries (`extDescription` in both
       locale files) and the screenshots, then paste the same changes into both dashboards so the
       two listings stay identical.
5. [ ] A new permission needs a new justification in both Privacy pages, and may lengthen review.
6. [ ] Edge: start the **Notes for certification** with what changed in this version.
7. [ ] Submit both. Manual installs are not updated by the stores; the release notes are how those
       users hear about a new version.
