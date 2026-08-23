import type { Translations } from "./en";

/**
 * Farsi, shipped from day one rather than retrofitted (spec §4.2).
 *
 * Numbers stay Latin: server operators read logs, IPs and byte counts in Latin
 * digits, and mixing scripts inside a metric hurts more than it helps.
 */
export const fa: Translations = {
  common: {
    appName: "فِروم",
    loading: "در حال بارگذاری…",
    retry: "تلاش دوباره",
    dismiss: "بستن",
    close: "بستن",
    cancel: "انصراف",
    signOut: "خروج",
    search: "جست‌وجو",
    none: "—",
    unknown: "نامشخص",
  },
  login: {
    title: "ورود",
    subtitle: "مدیریت سرور شما.",
    username: "نام کاربری",
    password: "گذرواژه",
    submit: "ورود",
    submitting: "در حال ورود…",
    usernameRequired: "نام کاربری را وارد کنید",
    passwordRequired: "گذرواژه را وارد کنید",
    genericError: "ورود ممکن نشد. اطلاعات را بررسی و دوباره تلاش کنید.",
    rateLimited: "تلاش‌های ناموفق زیاد بود. چند دقیقه دیگر دوباره تلاش کنید.",
  },
  nav: {
    dashboard: "داشبورد",
    tasks: "کارها",
    commandPalette: "جعبه فرمان",
    theme: "پوسته",
    language: "زبان",
    themeLight: "روشن",
    themeDark: "تیره",
    themeSystem: "سیستم",
  },
  dashboard: {
    title: "داشبورد",
    subtitle: "وضعیت زنده این سرور.",
    cpu: "پردازنده",
    memory: "حافظه",
    disk: "دیسک",
    load: "میانگین بار",
    uptime: "مدت روشن بودن",
    cores: "{{count}} هسته",
    cores_other: "{{count}} هسته",
    ofTotal: "از {{total}}",
    services: "سرویس‌ها",
    system: "سیستم",
    panelFootprint: "مصرف حافظه پنل",
    panelFootprintHint: "وب و عامل روی هم، در برابر سقف {{budget}}.",
    withinBudget: "در محدوده",
    overBudget: "فراتر از سقف",
    agentOffline: "عامل پاسخ نمی‌دهد",
    agentOfflineHint:
      "عملیات نیازمند دسترسی ریشه در دسترس نیست. سایت‌های شما سرو می‌شوند — nginx و PHP به پنل وابسته نیستند.",
    noServices: "هنوز سرویسی نصب نشده است.",
    installHint: "یک مؤلفه از پشته نصب کنید تا اینجا دیده شود.",
  },
  service: {
    active: "در حال اجرا",
    inactive: "متوقف",
    failed: "خطا",
    activating: "در حال شروع",
    deactivating: "در حال توقف",
    not_found: "نصب نشده",
    unknown: "نامشخص",
    enabled: "اجرا در بوت",
    disabled: "اجرای دستی",
  },
  tasks: {
    title: "کارها",
    empty: "هنوز کاری اجرا نشده است.",
    emptyHint: "کارهای طولانی اینجا با خروجی زنده نمایش داده می‌شوند.",
    active: "{{count}} در حال اجرا",
    status: {
      queued: "در صف",
      running: "در حال اجرا",
      ok: "انجام شد",
      failed: "ناموفق",
      cancelled: "لغو شد",
    },
    logs: "خروجی",
    noLogs: "هنوز خروجی‌ای نیست.",
    reconnected: "اتصال دوباره برقرار شد — بخشی از خروجی زنده جا افتاد. کار را دوباره باز کنید.",
  },
  error: {
    title: "خطایی رخ داد",
    requestId: "کد پیگیری: {{id}}",
  },
};
