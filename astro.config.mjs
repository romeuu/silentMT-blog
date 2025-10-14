import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import vercel from '@astrojs/vercel/static';

// https://astro.build/config
export default defineConfig({
  site: "https://s1lentmt.com",
  integrations: [sitemap({
    i18n: {
      defaultLocale: 'en',
      locales: {
        en: 'en-US',
        es: 'es-ES'
      },
      routing: {
        prefixDefaultLocale: true
      }
    }
  })],
  output: 'static',
  adapter: vercel(),
  build: {
    format: 'directory'
  }
});