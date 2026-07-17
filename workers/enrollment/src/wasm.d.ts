// wrangler/esbuild imports a `.wasm` file as a compiled `WebAssembly.Module`. Declare that shape so
// the Worker's own `tsc --noEmit` understands `import wasmModule from "...vortic_core_bg.wasm"`.
declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}
