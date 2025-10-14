export type SupportedLang = 'es' | 'en';
export const DEFAULT_LANG: SupportedLang = 'en';

export function getLang(pathname: string): SupportedLang {
  if (pathname.startsWith('/es')) return 'es';
  if (pathname.startsWith('/en')) return 'en';
  
  if (typeof navigator !== 'undefined') {
    const browserLang = navigator.language.split('-')[0];
    if (browserLang === 'es') return 'es';
  }
  
  return DEFAULT_LANG;
}

export function getAlternateLangPath(pathname: string): string {
  const currentLang = getLang(pathname);
  if (currentLang === 'es') {
    return pathname.replace(/^\/es/, '/en');
  }
  return pathname.replace(/^\/en/, '/es');
}