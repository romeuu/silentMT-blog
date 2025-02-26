export function getLanguage(url) {
    const language = url.startsWith('/es') ? 'es' : 'en';
    return language;
}  