// Starts the app; trunk injects no inline script, which the Content-Security-Policy forbids.
// `scripts/post_build.sh` rewrites these paths to the hashed `/assets/` bundle URLs before
// hashing `init.js` itself.
import init from "./e2ee_chat_web.js";

init({ module_or_path: "./e2ee_chat_web_bg.wasm" });
