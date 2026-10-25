import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
import {agentationDevelopmentPlugin} from "./devtools/agentation-dev-plugin.js";
import {fileURLToPath} from "node:url";
export default defineConfig({
 plugins:[react(),agentationDevelopmentPlugin()],
 base:"/",
 build:{
  outDir:fileURLToPath(new URL("../web/",import.meta.url)),
  emptyOutDir:true, assetsInlineLimit:0, cssCodeSplit:false, sourcemap:false,
  rollupOptions:{output:{entryFileNames:"app.js",chunkFileNames:"chunk-[name].js",
    assetFileNames:a=>a.names?.some(n=>n.endsWith(".css"))?"style.css":"[name][extname]"}}
 }
});
