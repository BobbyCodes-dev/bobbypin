/** Provider identity for deterministic composed analysis workflows. */
export const PINPOINT_WORKFLOW_PROVIDER = {
    id: "pinpoint-workflow",
    name: "PINPOINT composed investigation workflow",
    version: "1",
};
/** Provider identity for deterministic artifact inventories. */
export const ARTIFACT_GRAPH_PROVIDER = Object.freeze({
    id: "pinpoint-artifact-graph",
    name: "PINPOINT safe artifact graph provider",
    version: "1",
});
/** Provider identity for execution-free managed PE/CLI analysis. */
export const MANAGED_STATIC_PROVIDER = Object.freeze({
    id: "pinpoint-dotnet-static",
    name: "PINPOINT managed static analysis provider",
    version: "1",
});
/** Provider identity for portable, execution-free PE resource decoding. */
export const PE_RESOURCES_PROVIDER = Object.freeze({
    id: "pinpoint-pe-resources",
    name: "PINPOINT PE resource parser",
    version: "1",
});
/** Provider identity for portable, execution-free PE Authenticode table decoding. */
export const PE_CERTIFICATES_PROVIDER = Object.freeze({
    id: "pinpoint-pe-certificates",
    name: "PINPOINT PE certificate parser",
    version: "1",
});
/** Provider identity for portable, execution-free PE import-table decoding. */
export const PE_IMPORTS_PROVIDER = Object.freeze({
    id: "pinpoint-pe-imports",
    name: "PINPOINT PE import parser",
    version: "1",
});
/** Provider identity for portable, execution-free ELF note-table decoding. */
export const DEVICETREE_PROVIDER = Object.freeze({
    id: "pinpoint-devicetree",
    name: "PINPOINT flattened devicetree parser",
    version: "1",
});
export const ELF_NOTES_PROVIDER = Object.freeze({
    id: "pinpoint-elf-notes",
    name: "PINPOINT ELF note parser",
    version: "1",
});
/** Provider identity for portable, execution-free Apple .ips crash-report decoding. */
export const APPLE_IPS_PROVIDER = Object.freeze({
    id: "pinpoint-apple-ips",
    name: "PINPOINT Apple IPS parser",
    version: "1",
});
/** Provider identity for portable, execution-free Linux kernel-module metadata. */
export const KERNEL_MODULE_PROVIDER = Object.freeze({
    id: "pinpoint-kernel-module",
    name: "PINPOINT kernel module parser",
    version: "1",
});
/** Provider identity for execution-free Shannon byte-entropy profiling. */
export const BYTE_ENTROPY_PROVIDER = Object.freeze({
    id: "byte-entropy",
    name: "PINPOINT byte entropy",
    version: "1",
});
/** Provider identity for portable, execution-free PE and ELF export tables. */
export const NATIVE_EXPORTS_PROVIDER = Object.freeze({
    id: "pinpoint-native-exports",
    name: "PINPOINT PE/ELF export table reader",
    version: "1",
});
/** Provider identity for deterministic managed-code comparison workflows. */
export const MANAGED_WORKFLOW_PROVIDER = {
    id: "pinpoint-dotnet-workflows",
    name: "PINPOINT managed-code workflows",
    version: "1",
};
/** Provider identity for deterministic Apple application projections. */
export const APPLE_APPLICATION_PROVIDER = {
    id: "pinpoint-apple-application",
    name: "PINPOINT Apple application workflows",
    version: "1",
};
/** Provider identity for deterministic Android application projections. */
export const ANDROID_APPLICATION_PROVIDER = {
    id: "pinpoint-android-application",
    name: "PINPOINT Android application workflows",
    version: "1",
};
/** Provider identity for deterministic HarmonyOS application projections. */
export const HARMONY_APPLICATION_PROVIDER = {
    id: "pinpoint-harmony-application",
    name: "PINPOINT HarmonyOS application workflows",
    version: "1",
};
/** Provider identity for verified publication of retained website scripts. */
export const WEB_SCRIPT_EXPORT_PROVIDER = {
    id: "pinpoint-web-script-export",
    name: "PINPOINT captured script export",
    version: "1",
};
/** Provider identity for deterministic static JavaScript application analysis. */
export const JAVASCRIPT_APPLICATION_PROVIDER = {
    id: "pinpoint-javascript-application",
    name: "PINPOINT JavaScript application analyzer",
    version: "1",
};
/** Provider identity for static/passive-runtime JavaScript reconciliation. */
export const JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER = {
    id: "pinpoint-javascript-runtime-reconciliation",
    name: "PINPOINT JavaScript runtime reconciliation",
    version: "1",
};
/** Provider identity for selected views of retained analysis Evidence. */
export const ANALYSIS_VIEW_PROVIDER = {
    id: "pinpoint-analysis-view",
    name: "PINPOINT analysis view projection",
    version: "1",
};
/** Provider identity for graph-native feature tracing and version comparison. */
export const JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER = {
    id: "pinpoint-javascript-application-workflows",
    name: "PINPOINT JavaScript application workflows",
    version: "1",
};
/** Provider identity for deterministic Evidence bundle comparisons. */
export const BUNDLE_COMPARISON_PROVIDER = {
    id: "pinpoint-bundle-comparison",
    name: "PINPOINT Evidence bundle comparison",
    version: "1",
};
/** Provider identity for comparison-Evidence behavior aggregation. */
export const CHANGED_BEHAVIOR_PROVIDER = {
    id: "pinpoint-changed-behavior",
    name: "PINPOINT changed behavior investigation",
    version: "1",
};
/** Provider identity for Evidence-backed call-path reconstruction. */
export const CALL_PATH_PROVIDER = {
    id: "pinpoint-call-path",
    name: "PINPOINT call path reconstruction",
    version: "1",
};
/** Provider identity for explicit static/runtime hypothesis correlation. */
export const STATIC_RUNTIME_PROVIDER = {
    id: "pinpoint-static-runtime-correlation",
    name: "PINPOINT static/runtime correlation",
    version: "1",
};
/** Provider identity for finite reconstruction specification verification. */
export const RECONSTRUCTION_PROVIDER = {
    id: "pinpoint-reconstruction-verifier",
    name: "PINPOINT reconstruction verifier",
    version: "1",
};
export const PE_LOAD_CONFIG_PROVIDER = Object.freeze({
    id: "pinpoint-pe-load-config",
    name: "PINPOINT PE TLS/load-config parser",
    version: "1",
});
