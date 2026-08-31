import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import { en } from "./en";

/**
 * English only. The strings still live behind i18next rather than inline in
 * JSX so copy stays in one reviewable file and a second language remains an
 * import away, not a rewrite.
 */
void i18n.use(initReactI18next).init({
  resources: { en: { translation: en } },
  lng: "en",
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

export default i18n;
