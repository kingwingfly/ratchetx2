import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig, type Plugin } from "vitest/config";

// `worker-build 0.9` emits TC39 Source Phase Imports (`import source m from "./index_bg.wasm"`).
// Vite rewrites `import source` into a `.wasm?source` request handled by Node `fs.readFileSync`,
// which bypasses `@cloudflare/vitest-plugin`'s `CompiledWasm` externalizer (which matches bare
// `.wasm` and `.wasm?module`). Rewriting `import source` in the generated bundle to a plain
// `.wasm` default import hands workerd the exact same pre-compiled `WebAssembly.Module`.
function workerdWasmSourceImport(): Plugin {
  return {
    name: "workerd-wasm-source-import",
    enforce: "pre",
    transform(code, id) {
      if (!id.endsWith("/build/index.js") || !code.includes("import source ")) {
        return null;
      }
      return code.replace(
        /\bimport\s+source\s+([A-Za-z_$][\w$]*)\s+from\s*(["'][^"']+\.wasm["'])/g,
        "import $1 from $2",
      );
    },
  };
}

export default defineConfig({
  plugins: [
    workerdWasmSourceImport(),
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.test.toml",
      },
    }),
  ],
  test: {
    include: ["tests/workerd/**/*.test.ts"],
  },
});
