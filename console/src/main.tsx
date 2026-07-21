import { createRoot } from "react-dom/client";
import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/base.css";
import { App } from "./App";

// The console is a faithful port of the prototype's single streaming component: a root
// React.Component class (App) that owns all state + methods, rendering the shell + routed
// screens + overlays. App IS the state authority, exactly like `class Component extends DCLogic`.
// (No StrictMode — the demo tick-loop uses real timers we don't want double-mounted in dev.)
createRoot(document.getElementById("root")!).render(<App />);
