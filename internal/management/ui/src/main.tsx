import React from "react";
import { createRoot } from "react-dom/client";
import { setupIonicReact } from "@ionic/react";
import App from "./App";

// Ionic core + baseline utility styles.
import "@ionic/react/css/core.css";
import "@ionic/react/css/normalize.css";
import "@ionic/react/css/structure.css";
import "@ionic/react/css/typography.css";
import "@ionic/react/css/padding.css";
import "@ionic/react/css/flex-utils.css";
import "@ionic/react/css/display.css";
import "@ionic/react/css/palettes/dark.system.css"; // follow the OS light/dark preference
import "./theme.css";

setupIonicReact();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
