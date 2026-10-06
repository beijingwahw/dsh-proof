/**
 * Ports — the only way the `dsh-proof` core touches the outside world.
 *
 * The core is a pure domain layer: it never imports `@deepseek-ai/*`, never
 * opens a socket, and never reads `process`. Everything it needs arrives
 * through these interfaces. That is the "interface / implementation / consumer"
 * split DSH itself prescribes — the DSH adapter (`src/dsh/`) is just one
 * implementation of these ports, and the test suite is another.
 *
 * @module dsh-proof/core/ports
 */
export {};
//# sourceMappingURL=ports.js.map