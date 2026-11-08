import { PROCESS_PROVIDER, isProcessEvidenceProvider, } from "./process/processEvidenceProvider.js";
/** Canonical provider identity for deterministic artifact comparisons. */
export const ARTIFACT_COMPARISON_PROVIDER = {
    id: "pinpoint-artifact-comparison",
    name: "PINPOINT artifact comparison",
    version: "1",
};
/** Canonical provider identity for deterministic function comparisons. */
export const FUNCTION_COMPARISON_PROVIDER = {
    id: "pinpoint-function-comparison",
    name: "PINPOINT function comparison",
    version: "1",
};
const COMPARISON_EVIDENCE_IDENTITIES = {
    compare_artifacts: {
        predicate: "pinpoint.artifact-comparison",
        provider: ARTIFACT_COMPARISON_PROVIDER,
    },
    compare_functions: {
        predicate: "pinpoint.function-comparison",
        provider: FUNCTION_COMPARISON_PROVIDER,
    },
    compare_process_captures: {
        predicate: "pinpoint.process-comparison",
        provider: PROCESS_PROVIDER,
    },
};
/** Whether an operation is one of the comparison workflows this domain owns. */
export const isComparisonEvidenceOperation = (operation) => Object.hasOwn(COMPARISON_EVIDENCE_IDENTITIES, operation);
/** Check shared Evidence identity without imposing a consumer's link policy. */
export const hasComparisonEvidenceIdentity = (evidence) => {
    if (!isComparisonEvidenceOperation(evidence.operation))
        return false;
    const expected = COMPARISON_EVIDENCE_IDENTITIES[evidence.operation];
    const providerMatches = evidence.operation === "compare_process_captures"
        ? isProcessEvidenceProvider(evidence.provider)
        : evidence.provider.id === expected.provider.id &&
            evidence.provider.name === expected.provider.name &&
            evidence.provider.version === expected.provider.version;
    return (evidence.predicate_type === expected.predicate &&
        providerMatches &&
        evidence.confidence === "derived" &&
        evidence.authority === "analyst-inference" &&
        evidence.subject === null);
};
