import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { applyThemePreference, readThemePreference } from "@nopass/ui";
import "./index.css";
import { App } from "./App";

// Apply the stored theme override (if any) before first paint; otherwise the
// theme follows prefers-color-scheme through theme.css
applyThemePreference(readThemePreference());

const root = document.getElementById("root");
if (root) createRoot(root).render(<StrictMode><App /></StrictMode>);
