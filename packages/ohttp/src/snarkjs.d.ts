// snarkjs ships no TypeScript declarations. Minimal ambient module covering only what
// live.e2e.test.ts actually calls — not a full snarkjs API surface. Mirrors
// apps/web/src/lib/snarkjs.d.ts (this package's copy needs its own since it's a separate
// TS project, not shared config).
declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{
      proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
      publicSignals: string[];
    }>;
  };
}
