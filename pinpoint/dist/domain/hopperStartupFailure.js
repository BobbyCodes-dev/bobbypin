const failures = [
    [
        70,
        "private_display_unavailable",
        "PINPOINT could not start its private Linux display. Install Xvfb, then rerun pinpoint doctor.",
    ],
    [
        71,
        "x11_authorization_failed",
        "PINPOINT could not authorize its private Linux display. Install xauth, then rerun pinpoint doctor.",
    ],
    [
        72,
        "unsupported_hopper_build",
        "This Hopper build is not supported for unattended Linux analysis. Unset HOPPER_LAUNCHER_PATH and rerun pinpoint setup --yes --install-hopper, or update PINPOINT.",
    ],
    [
        73,
        "invalid_launch_command",
        "PINPOINT refused an unexpected Hopper launch command. Check HOPPER_LAUNCHER_PATH and rerun pinpoint doctor.",
    ],
    [
        74,
        "process_ownership_mismatch",
        "PINPOINT could not verify ownership of the launched Hopper process and stopped safely. Close other Hopper sessions and retry.",
    ],
    [
        75,
        "hopper_exited_during_startup",
        "Hopper exited before the PINPOINT bridge was ready. In CI, run pinpoint doctor --provider hopper --json; if Hopper showed a UI or license prompt, complete it in the runner user session, otherwise close stale Hopper sessions and retry.",
    ],
    [
        76,
        "unsupported_demo_dialog",
        "This Hopper demo dialog is not supported for unattended Linux analysis. Update PINPOINT or use a supported Hopper build.",
    ],
    [
        77,
        "unexpected_display_geometry",
        "PINPOINT's private Linux display did not match the validated layout. Close custom display overrides and retry.",
    ],
    [
        78,
        "x11_input_failed",
        "PINPOINT could not activate Hopper's validated demo control. Install the XTEST runtime, then rerun pinpoint doctor.",
    ],
    [
        79,
        "runtime_dependency_unavailable",
        "A Linux demo-session dependency is unavailable. Rerun pinpoint setup --yes --install-hopper, then pinpoint doctor.",
    ],
    [
        80,
        "x11_socket_directory_unusable",
        "PINPOINT cannot use the host X11 socket directory for a private display. Run pinpoint doctor --provider hopper for exact mount and namespace diagnostics.",
    ],
];
const HOPPER_STARTUP_FAILURES = new Map(failures.map(([exitCode, code, message]) => [exitCode, { code, message }]));
/** Return the stable public failure associated with a Linux demo adapter exit. */
export const hopperStartupFailure = (exitCode) => exitCode === null ? undefined : HOPPER_STARTUP_FAILURES.get(exitCode);
/** Return the adapter exit associated with one stable startup failure code. */
export const hopperStartupExitCode = (code) => failures.find(([, candidate]) => candidate === code)?.[0];
/** Narrow an untrusted diagnostic field to the public startup code union. */
export const isHopperStartupFailureCode = (value) => failures.some(([, candidate]) => candidate === value);
