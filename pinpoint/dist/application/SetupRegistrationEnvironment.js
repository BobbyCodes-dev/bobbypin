import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
const SELECTED_REGISTRATION_SETTINGS = [
    "PINPOINT_ANALYSIS_PROVIDER",
    "PINPOINT_ASAR_MAX_HEADER_BYTES",
    "PINPOINT_BRIDGE_MAX_REQUEST_BYTES",
    "PINPOINT_CAPTURE_DECODER_OLD_GENERATION_MIB",
    "PINPOINT_GHIDRA_DECOMPILE_TIMEOUT_SECONDS",
    "PINPOINT_GHIDRA_STARTUP_TIMEOUT_MS",
    "PINPOINT_HOPPER_STARTUP_TIMEOUT_MS",
    "PINPOINT_JEB_MCP_TIMEOUT_MS",
    "PINPOINT_MCP_INPUT_SCHEMA_PROFILE",
    "PINPOINT_REGEX_MATCHING_DEADLINE_MS",
    "PINPOINT_REGEX_WORKER_HEAP_REQUEST_MIB",
    "PINPOINT_MCP_INITIALIZE_BUDGET_MS",
    "PINPOINT_MCP_TOOLS_LIST_BUDGET_MS",
    "PINPOINT_MCP_FIRST_CATALOG_BUDGET_MS",
    "PINPOINT_MCP_DOCTOR_DEADLINE_MS",
];
/** Preserve selected setup settings without copying unrelated process values. */
export const explicitSetupRegistrationEnvironment = (environment) => Object.fromEntries(SELECTED_REGISTRATION_SETTINGS.flatMap((key) => {
    const value = environment[key];
    return value === undefined ? [] : [[key, value]];
}));
/** Preserve adapter-published settings independently of runtime readiness. */
export const providerRegistrationEnvironment = (inspections) => Object.fromEntries(inspections
    .flatMap(({ registrationEnvironment }) => Object.entries(registrationEnvironment))
    .sort(([left], [right]) => compareUnicodeCodePoints(left, right)));
