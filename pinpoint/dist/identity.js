/**
 * Canonical public identity shared by packaging, setup, MCP, and skill install.
 * Centralization prevents persistent client registrations from drifting from
 * the npm package or executable exposed in package.json.
 */
export const PRODUCT_IDENTITY = {
    displayName: "PINPOINT",
    packageName: PACKAGE_METADATA.name,
    packageSpecifier: `${PACKAGE_METADATA.name}@latest`,
    registrationPackageSpecifier: `${PACKAGE_METADATA.name}@${PACKAGE_METADATA.version}`,
    packageVersion: PACKAGE_METADATA.version,
    cliBinary: "pinpoint",
    mcpCommand: "pinpoint mcp",
    mcpServerKey: "pinpoint",
    skillName: "pinpoint",
    skillVersion: PACKAGE_METADATA.skillVersion,
    configFileName: "pinpoint.json",
};
/** Exact SDK package identities, distinct from negotiated protocol version. */
export const SDK_IDENTITY = {
    server: PACKAGE_METADATA.serverSdkVersion,
    client_test: PACKAGE_METADATA.clientSdkVersion,
    core: PACKAGE_METADATA.coreSdkVersion,
};
import { PACKAGE_METADATA } from "./generatedPackageMetadata.js";
