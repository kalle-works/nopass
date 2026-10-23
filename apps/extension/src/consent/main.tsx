import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { applyThemePreference, readThemePreference } from "@nopass/ui";
import "../popup/index.css";
import { Consent } from "./Consent";

applyThemePreference(readThemePreference());

const requestId = new URLSearchParams(window.location.search).get("id") ?? "";
const root = document.getElementById("root");
if (root) createRoot(root).render(<StrictMode><Consent requestId={requestId} /></StrictMode>);
