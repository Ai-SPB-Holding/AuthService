const dict = {
  en: {
    login: "Sign In",
    dashboard: "Dashboard",
    users: "Users",
  },
  ru: {
    login: "Войти",
    dashboard: "Панель",
    users: "Пользователи",
  },
};

export type Lang = keyof typeof dict;

let lang: Lang = "ru";

export function setLang(next: Lang) {
  lang = next;
}

export function t(key: keyof (typeof dict)["en"]) {
  return dict[lang][key];
}
