import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";

//#region dist/browser/providerIdentities.js
var CDP_BROWSER_PROVIDER_IDENTITY, PLAYWRIGHT_BROWSER_SCENARIO_PROVIDER_IDENTITY, CDP_ELECTRON_PROVIDER_IDENTITY, PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_IDENTITY;
function init_providerIdentities() {
	return (init_providerIdentities = __esmMin((() => {
		CDP_BROWSER_PROVIDER_IDENTITY = Object.freeze({
			id: "pinpoint-cdp-browser",
			name: "PINPOINT Chrome DevTools Protocol observation provider",
			version: "2"
		});
		PLAYWRIGHT_BROWSER_SCENARIO_PROVIDER_IDENTITY = Object.freeze({
			id: "pinpoint-playwright-browser-scenario",
			name: "PINPOINT Playwright browser scenario capture provider",
			version: "1"
		});
		CDP_ELECTRON_PROVIDER_IDENTITY = Object.freeze({
			id: "pinpoint-cdp-electron",
			name: "PINPOINT Electron file-page CDP observation provider",
			version: "1"
		});
		PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_IDENTITY = Object.freeze({
			id: "pinpoint-playwright-electron-active",
			name: "PINPOINT Playwright active Electron observation provider",
			version: "1"
		});
	})))();
}

//#endregion
export { CDP_BROWSER_PROVIDER_IDENTITY, CDP_ELECTRON_PROVIDER_IDENTITY, PLAYWRIGHT_BROWSER_SCENARIO_PROVIDER_IDENTITY, PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_IDENTITY, init_providerIdentities };