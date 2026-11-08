import { accessSync, constants, statSync } from "node:fs";
import { ConfigurationError, } from "../domain/configurationErrors.js";
import { err, ok } from "../domain/result.js";
import { parseEnvironment } from "./environment.js";
import { providerStartupTimeoutSchema } from "./providerStartupTimeout.js";
import { homeDirectoryFromEnvironment } from "./homeDirectory.js";
import { DEFAULT_BRIDGE_MAX_REQUEST } from "./bridgeMaxRequestBytes.js";
import { DEFAULT_REGEX_MATCHING_DEADLINE } from "./regexMatchingDeadline.js";
import { DEFAULT_REGEX_WORKER_HEAP_REQUEST } from "./regexWorkerHeapRequest.js";
import { hopperLauncherDiscovery } from "../application/HopperLauncherDiscovery.js";
import { localMacHopperRenamedLauncherCandidates } from "../application/MacHopperPaths.js";
const executableAvailable = (path) => {
    try {
        accessSync(path, constants.X_OK);
        return statSync(path).isFile();
    }
    catch {
        return false;
    }
};
export const defaultHopperLauncherPath = (platform, homeDirectory, executable = executableAvailable) => {
    const discovery = hopperLauncherDiscovery(platform, homeDirectory);
    for (const candidate of discovery.candidates)
        if (executable(candidate))
            return candidate;
    if (discovery.probesMacApplicationBundles)
        for (const candidate of localMacHopperRenamedLauncherCandidates(homeDirectory))
            if (executable(candidate))
                return candidate;
    return discovery.fallback;
};
/**
 * Environment native analysis admits. JEB validates its own timeout during
 * optional provider composition; that setting must not block unrelated
 * CLI/MCP startup. Registration validation still checks it directly.
 */
const nativeAnalysisEnvironment = (environment) => {
    const { PINPOINT_JEB_MCP_TIMEOUT_MS: _jebTimeout, ...appEnvironment } = environment;
    return appEnvironment;
};
/** Inspect native admission without probing launchers or losing mixed-invalid diagnostics. */
export const inspectNativeAnalysisConfiguration = (environment) => {
    const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
    const issues = parsed.ok ? [] : parsed.error.settings;
    const configuredTimeout = environment.PINPOINT_HOPPER_STARTUP_TIMEOUT_MS;
    if (configuredTimeout === undefined)
        return { issues };
    if (parsed.ok)
        return {
            issues,
            configuredHopperStartupTimeout: ok(parsed.value.PINPOINT_HOPPER_STARTUP_TIMEOUT_MS),
        };
    // Another setting may reject the aggregate before this supplied timeout's
    // facts are available. Its dedicated diagnostic still uses the same schema.
    const timeout = providerStartupTimeoutSchema.safeParse(configuredTimeout);
    return {
        issues,
        configuredHopperStartupTimeout: timeout.success
            ? ok(timeout.data)
            : err(new ConfigurationError("Invalid PINPOINT environment configuration", {
                cause: timeout.error,
                settings: timeout.error.issues.map(({ message }) => ({
                    setting: "PINPOINT_HOPPER_STARTUP_TIMEOUT_MS",
                    constraint: message,
                })),
            })),
    };
};
/** Parse provider configuration and runtime prerequisites at the composition root. */
export const parseConfig = (environment) => {
    const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
    if (!parsed.ok)
        return parsed;
    const env = parsed.value;
    return ok({
        ...(env.PINPOINT_MCP_MAX_RESPONSE_BYTES === undefined
            ? {}
            : { mcpMaxResponseBytes: env.PINPOINT_MCP_MAX_RESPONSE_BYTES }),
        ...(env.PINPOINT_MCP_INPUT_SCHEMA_PROFILE === undefined
            ? {}
            : { mcpInputSchemaProfile: env.PINPOINT_MCP_INPUT_SCHEMA_PROFILE }),
        ...(env.PINPOINT_MCP_OUTPUT_SCHEMA_PROFILE === undefined
            ? {}
            : { mcpOutputSchemaProfile: env.PINPOINT_MCP_OUTPUT_SCHEMA_PROFILE }),
        analysisProvider: env.PINPOINT_ANALYSIS_PROVIDER,
        ...(env.PINPOINT_IDA_MCP_CONFIG === undefined
            ? {}
            : { idaMcpConfigPath: env.PINPOINT_IDA_MCP_CONFIG }),
        ghidraInstallDir: env.GHIDRA_INSTALL_DIR,
        ghidraJavaHome: env.JAVA_HOME,
        ghidraStartupTimeoutMs: env.PINPOINT_GHIDRA_STARTUP_TIMEOUT_MS,
        ...(env.PINPOINT_GHIDRA_DECOMPILE_TIMEOUT_SECONDS === undefined
            ? {}
            : {
                ghidraDecompileTimeoutSeconds: env.PINPOINT_GHIDRA_DECOMPILE_TIMEOUT_SECONDS,
            }),
        ...(env.PINPOINT_GHIDRA_LANGUAGE_ID === undefined
            ? {}
            : {
                ghidraLanguageOverride: {
                    languageId: env.PINPOINT_GHIDRA_LANGUAGE_ID,
                    ...(env.PINPOINT_GHIDRA_COMPILER_SPEC_ID === undefined
                        ? {}
                        : { compilerSpecId: env.PINPOINT_GHIDRA_COMPILER_SPEC_ID }),
                },
            }),
        ...(env.PINPOINT_GHIDRA_SEED_FILE === undefined
            ? {}
            : { ghidraSeedFile: env.PINPOINT_GHIDRA_SEED_FILE }),
        ...(env.PINPOINT_GHIDRA_DISABLED_ANALYZERS === undefined
            ? {}
            : { ghidraDisabledAnalyzers: env.PINPOINT_GHIDRA_DISABLED_ANALYZERS }),
        ...(env.PINPOINT_GHIDRA_NATIVEAOT_JAR === undefined
            ? {}
            : { ghidraNativeAotJar: env.PINPOINT_GHIDRA_NATIVEAOT_JAR }),
        ilspyCmdPath: env.PINPOINT_ILSPY_CMD_PATH,
        hopperLauncherPath: env.HOPPER_LAUNCHER_PATH ??
            defaultHopperLauncherPath(process.platform, homeDirectoryFromEnvironment(environment, process.platform)),
        hopperStartupTimeoutMs: env.PINPOINT_HOPPER_STARTUP_TIMEOUT_MS,
        hopperTargetPath: env.HOPPER_TARGET_PATH,
        hopperTargetKind: env.HOPPER_TARGET_KIND,
        hopperLoaderArgs: env.loaderArgs,
        logLevel: env.PINPOINT_LOG_LEVEL,
        referenceSourcePolicy: {
            secretPatterns: env.referenceSecretPatterns,
        },
        bridgeMaxRequestBytes: env.PINPOINT_BRIDGE_MAX_REQUEST_BYTES === undefined
            ? DEFAULT_BRIDGE_MAX_REQUEST
            : {
                maximumBytes: env.PINPOINT_BRIDGE_MAX_REQUEST_BYTES,
                source: "setting",
            },
        regexMatchingDeadline: env.PINPOINT_REGEX_MATCHING_DEADLINE_MS === undefined
            ? DEFAULT_REGEX_MATCHING_DEADLINE
            : {
                deadlineMs: env.PINPOINT_REGEX_MATCHING_DEADLINE_MS,
                source: "setting",
            },
        regexWorkerHeapRequest: env.PINPOINT_REGEX_WORKER_HEAP_REQUEST_MIB === undefined
            ? DEFAULT_REGEX_WORKER_HEAP_REQUEST
            : {
                heapMiB: env.PINPOINT_REGEX_WORKER_HEAP_REQUEST_MIB,
                source: "setting",
            },
    });
};
