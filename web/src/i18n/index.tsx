import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { en } from "./en";
import { zhCN } from "./zh-CN";

type Locale = "zh-CN" | "en";
type TranslationKey = keyof typeof zhCN;

interface I18nValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: TranslationKey) => string;
}

const I18nContext = createContext<I18nValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    try {
      return window.localStorage.getItem("agentera.locale") === "en" ? "en" : "zh-CN";
    } catch {
      return "zh-CN";
    }
  });
  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    document.documentElement.lang = next;
    try {
      window.localStorage.setItem("agentera.locale", next);
    } catch {
      // Locale remains active for the current page.
    }
  }, []);
  const value = useMemo<I18nValue>(() => ({
    locale,
    setLocale,
    t: (key) => (locale === "en" ? en[key] : zhCN[key]),
  }), [locale, setLocale]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (!value) {
    throw new Error("I18nProvider is required");
  }
  return value;
}
