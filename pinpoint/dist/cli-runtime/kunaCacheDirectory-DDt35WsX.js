import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { isAbsolute, join } from "node:path";

//#region dist/config/kunaCacheDirectory.js
var defaultKunaCacheDirectory;
function init_kunaCacheDirectory() {
	return (init_kunaCacheDirectory = __esmMin((() => {
		defaultKunaCacheDirectory = (home, environment, platform) => {
			if (platform === "darwin") return join(home, "Library", "Caches", "pinpoint", "kuna");
			const xdg = environment.XDG_CACHE_HOME;
			return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(home, ".cache"), "pinpoint", "kuna");
		};
	})))();
}

//#endregion
export { defaultKunaCacheDirectory, init_kunaCacheDirectory };