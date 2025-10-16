(async () => {
  const results = [];

  const log = (name, data) => {
    if (!data) return;
    const output = Array.isArray(data)
      ? data.join('\n')
      : typeof data === 'object'
      ? JSON.stringify(data, null, 2)
      : String(data);

    if (output.trim()) {
      console.group(`📦 ${name}`);
      console.log(output);
      console.groupEnd();
      results.push(name);
    }
  };

  try {
    // === Next.js ===
    if (window.__BUILD_MANIFEST)
      log('Next.js pages', window.__BUILD_MANIFEST.sortedPages);
    if (window.__NEXT_DATA__)
      log('Next.js __NEXT_DATA__', window.__NEXT_DATA__);
    const nextLinks = [...document.querySelectorAll('link[as="script"]')].map(l => l.href);
    if (nextLinks.length) log('Next.js preload links', nextLinks);

    // === Nuxt.js ===
    if (window.$nuxt?.$router?.options?.routes)
      log('Nuxt 2 routes', window.$nuxt.$router.options.routes.map(r => r.path));
    if (window.__NUXT__) {
      log('Nuxt 3 data', window.__NUXT__.data);
      log('Nuxt 3 config', window.__NUXT__.config);
    }
    if (window.$nuxt?.$router?.getRoutes)
      log('Nuxt getRoutes()', window.$nuxt.$router.getRoutes().map(r => r.path));

    // === Gatsby ===
    if (window.___loader?.pageDataDb) {
      log('Gatsby pages', Object.keys(window.___loader.pageDataDb));
      log('Gatsby hoveredPaths', window.___loader.hoveredPaths);
    }
    if (window.___webpackCompilationHash)
      log('Gatsby webpack hash', window.___webpackCompilationHash);

    // === SvelteKit ===
    if (window.__sveltekit_) log('SvelteKit global', window.__sveltekit_);
    if (window.__sveltekit_navigation) log('SvelteKit navigation', window.__sveltekit_navigation);
    const svelteKeys = Object.keys(window).filter(k => k.includes('svelte'));
    if (svelteKeys.length) log('Svelte-related globals', svelteKeys);

    // === Angular ===
    try {
      const ngRoutes = getAllAngularRootElements?.()[0]
        ?.injector
        ?.get('Router')
        ?.config
        ?.map(r => r.path);
      if (ngRoutes?.length) log('Angular routes', ngRoutes);
    } catch {}
    try {
      const ngProbe = ng?.probe(getAllAngularRootElements?.()[0])?.injector?.get('Router')?.config;
      if (ngProbe?.length) log('Angular probe routes', ngProbe.map(r => r.path));
    } catch {}
    const angularLinks = Array.from(document.querySelectorAll('[routerlink]')).map(el => el.getAttribute('routerlink'));
    if (angularLinks.length) log('Angular [routerlink] elements', angularLinks);

    // === Remix ===
    if (window.__remixManifest) log('Remix manifest', window.__remixManifest);
    if (window.__remixContext) log('Remix context', window.__remixContext);
    const remixKeys = Object.keys(window).filter(k => k.includes('remix'));
    if (remixKeys.length) log('Remix-related globals', remixKeys);

    // === Astro ===
    const astroIslands = document.querySelectorAll('astro-island');
    if (astroIslands.length) log('Astro islands', Array.from(astroIslands).map(i => i.getAttribute('component-url')));
    const astroScripts = [...document.querySelectorAll('script[type="module"]')]
      .map(s => s.src)
      .filter(src => src.includes('astro'));
    if (astroScripts.length) log('Astro module scripts', astroScripts);

    // === Solid.js / SolidStart ===
    if (window._$HY) log('Solid.js hydration data', window._$HY);
    const solidKeys = Object.keys(window).filter(k => k.includes('solid') || k.includes('_$'));
    if (solidKeys.length) log('Solid-related globals', solidKeys);

    // === Qwik ===
    if (window.qwikevents) log('Qwik events', window.qwikevents);
    const qwikContainers = document.querySelectorAll('[q\\:container]');
    if (qwikContainers.length) log('Qwik containers', qwikContainers.length);
    const qwikKeys = Object.keys(window).filter(k => k.includes('qwik'));
    if (qwikKeys.length) log('Qwik-related globals', qwikKeys);

    // === Ember.js ===
    if (window.Ember) {
      try {
        const app = window.Ember.Application.NAMESPACES.find(ns => ns instanceof window.Ember.Application);
        const router = app?.__container__?.lookup('router:main');
        if (router?.router?.recognizer?.names) {
          log('Ember routes', Object.keys(router.router.recognizer.names));
        }
      } catch {}
    }
    const emberLinks = [...document.querySelectorAll('[href*="ember"]')].map(a => a.href);
    if (emberLinks.length) log('Ember-related links', emberLinks);

    // === Vite ===
    if (window.__vite_plugin_react_preamble_installed__) log('Vite React detected', true);
    const viteScripts = [...document.querySelectorAll('script[type="module"]')]
      .map(s => s.src)
      .filter(src => src.includes('@vite') || src.includes('/@id/'));
    if (viteScripts.length) log('Vite module scripts', viteScripts);

    // === Parcel ===
    const parcelKeys = Object.keys(window).filter(k => k.includes('parcel'));
    if (parcelKeys.length) log('Parcel-related globals', parcelKeys);

    // === Create React App ===
    if (document.getElementById('root')?._reactRootContainer) log('Create React App detected', true);

    // === Vue Router (generic) ===
    if (window.$vm?.$router?.options?.routes)
      log('Vue Router (vm)', window.$vm.$router.options.routes.map(r => r.path));
    const vueApp = document.querySelector('#app');
    if (vueApp?.__vue__?.$router?.options?.routes)
      log('Vue 2 router', vueApp.__vue__.$router.options.routes.map(r => r.path));
    if (vueApp?.__vue_app__?.config?.globalProperties?.$router?.getRoutes)
      log('Vue 3 router', vueApp.__vue_app__.config.globalProperties.$router.getRoutes().map(r => r.path));

    // === Backbone.js ===
    if (window.Backbone?.history?.handlers) {
      log('Backbone routes', window.Backbone.history.handlers.map(h => h.route.toString()));
    }

    // === Meteor ===
    if (window.Meteor) log('Meteor detected', window.Meteor.release);
    if (window.FlowRouter?.routes) {
      log('Meteor FlowRouter', window.FlowRouter.routes.map(r => r.path));
    }

    // === Jekyll / Static Sites ===
    const jekyllMeta = document.querySelector('meta[name="generator"][content*="Jekyll"]');
    if (jekyllMeta) log('Jekyll detected', jekyllMeta.content);

    // === WordPress ===
    const wpMeta = document.querySelector('meta[name="generator"][content*="WordPress"]');
    if (wpMeta) log('WordPress detected', wpMeta.content);
    if (window.wp) log('WordPress wp object', Object.keys(window.wp));

    // === Drupal ===
    if (window.Drupal) log('Drupal detected', Object.keys(window.Drupal));

    // === Universal ===
    try {
      const sitemap = await fetch('/sitemap.xml').then(r => r.text());
      if (sitemap) log('Sitemap.xml', sitemap.slice(0, 1000));
    } catch {}
    try {
      const robots = await fetch('/robots.txt').then(r => r.text());
      if (robots) log('robots.txt', robots);
    } catch {}

    const links = [...document.querySelectorAll('a')]
      .map(a => a.href)
      .filter((v, i, a) => a.indexOf(v) === i && v.startsWith(window.location.origin))
      .sort();
    if (links.length) log('Internal links on page', links);

    const webpackKeys = Object.keys(window).filter(k => k.includes('webpack'));
    if (webpackKeys.length) log('Webpack chunks', webpackKeys);

    try {
      const swRegs = await navigator.serviceWorker.getRegistrations();
      if (swRegs.length) log('Service Workers', swRegs.map(r => r.scope));
    } catch {}

    // === GraphQL / Apollo ===
    if (window.__APOLLO_STATE__) log('Apollo GraphQL state', window.__APOLLO_STATE__);
    if (window.__APOLLO_CLIENT__) log('Apollo Client detected', true);

    // === Redux ===
    if (window.__REDUX_DEVTOOLS_EXTENSION__) log('Redux DevTools detected', true);
    const reduxKeys = Object.keys(window).filter(k => k.includes('redux') || k.includes('REDUX'));
    if (reduxKeys.length) log('Redux-related globals', reduxKeys);

  } catch (err) {
    console.error('Помилка при аналізі:', err);
  }

  if (!results.length) {
    console.warn('⚠️ Роути не знайдено. Можливо, фреймворк не підтримується або дані приховані при збірці.');
  } else {
    console.log(`✅ Знайдено роути/дані в: ${results.join(', ')}`);
  }
})();
