// Vite resolves a `?url` import suffix to the emitted asset's URL string. This package is consumed
// from source by the app's Vite pipeline, but its OWN `tsc --noEmit` has no Vite ambient types, so
// declare the one asset form `crypto.ts` uses. (A full `vite/client` reference would pull a Vite
// dependency this crypto package doesn't otherwise need.)
declare module "*?url" {
  const url: string;
  export default url;
}
