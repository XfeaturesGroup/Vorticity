// snarkjs ships no TypeScript declarations. Minimal ambient module covering only what `zkProof.ts`
// actually calls — not a full snarkjs API surface.
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
