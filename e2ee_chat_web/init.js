// Starts the app; trunk injects no inline script, which the Content-Security-Policy forbids.
import init from "./e2ee_chat_web.js";

init({ module_or_path: "./e2ee_chat_web_bg.wasm" });
