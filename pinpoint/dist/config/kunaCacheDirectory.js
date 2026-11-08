import { isAbsolute, join } from "node:path";
/** Per-user cache directory that PINPOINT owns for Kuna on this host. */
export const defaultKunaCacheDirectory = (home, environment, platform) => {
    if (platform === "darwin")
        return join(home, "Library", "Caches", "pinpoint", "kuna");
    const xdg = environment.XDG_CACHE_HOME;
    return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(home, ".cache"), "pinpoint", "kuna");
};
