/** Required packaged sources, selected by their runtime role rather than order. */
export const GHIDRA_BRIDGE_SOURCES = Object.freeze({
    bridge: "PinpointGhidraBridge.java",
    bundleActivator: "PinpointGhidraBundleActivator.java",
    extensions: "PinpointGhidraExtensions.java",
    prepareCom: "PinpointGhidraPrepareCom.java",
    prepareRaw: "PinpointGhidraPrepareRaw.java",
    prepareDol: "PinpointGhidraPrepareDol.java",
    applySeeds: "PinpointGhidraApplySeeds.java",
    analysisOptions: "PinpointGhidraAnalysisOptions.java",
    noReturnFix: "PinpointGhidraNoReturnFix.java",
    mipsSoftFloat: "PinpointGhidraMipsSoftFloat.java",
});
