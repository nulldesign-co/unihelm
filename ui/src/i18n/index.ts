import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import { en } from "./en";
import { fa } from "./fa";

export const LANGUAGES = [
  { code: "en", label: "English", dir: "ltr" as const },
  { code: "fa", label: "فارسی", dir: "rtl" as const },
];

export type LanguageCode = (typeof LANGUAGES)[number]["code"];

const STORAGE_KEY = "ferrum.lang";

function initialLanguage(): string {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored && LANGUAGES.some((l) => l.code === stored)) return stored;
  // Match the browser only on the base tag: `fa-IR` and `fa` are the same choice.
  const browser = navigator.language.split("-")[0] ?? "en";
  return LANGUAGES.some((l) => l.code === browser) ? browser : "en";
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, fa: { translation: fa } },
  lng: initialLanguage(),
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

/** Apply the language to the document, including writing direction. */
export function applyLanguage(code: string) {
  const language = LANGUAGES.find((l) => l.code === code) ?? LANGUAGES[0]!;
  localStorage.setItem(STORAGE_KEY, language.code);
  document.documentElement.lang = language.code;
  // RTL is a document-level property; every layout below uses logical
  // properties so nothing needs a mirrored stylesheet (spec §16.9).
  document.documentElement.dir = language.dir;
  void i18n.changeLanguage(language.code);
}

applyLanguage(i18n.language);

export default i18n;
