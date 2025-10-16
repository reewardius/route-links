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

  // === Technology Detection ===
  const detectTechnologies = () => {
    const techs = {};

    // Frameworks
    if (window.__NEXT_DATA__) techs['Next.js'] = window.__NEXT_DATA__.buildId || 'detected';
    if (window.$nuxt) techs['Nuxt.js'] = window.$nuxt?.constructor?.version || '2.x';
    if (window.__NUXT__) techs['Nuxt.js'] = '3.x';
    if (window.___loader) techs['Gatsby'] = window.___webpackCompilationHash || 'detected';
    if (window.__sveltekit_) techs['SvelteKit'] = 'detected';
    if (window.Ember) techs['Ember.js'] = window.Ember.VERSION;
    if (window.Angular || window.getAllAngularRootElements) techs['Angular'] = window.ng?.version?.full || 'detected';
    if (window.__remixManifest) techs['Remix'] = 'detected';
    if (window.React) techs['React'] = window.React.version;
    if (window.Vue) techs['Vue.js'] = window.Vue.version;
    if (window.Backbone) techs['Backbone.js'] = window.Backbone.VERSION;
    if (window.Meteor) techs['Meteor'] = window.Meteor.release;
    if (window._$HY) techs['Solid.js'] = 'detected';
    if (window.qwikevents) techs['Qwik'] = 'detected';
    if (document.querySelectorAll('astro-island').length) techs['Astro'] = 'detected';

    // Libraries
    if (window.jQuery) techs['jQuery'] = window.jQuery.fn.jquery;
    if (window.$) techs['jQuery or Zepto'] = window.$.fn?.jquery || 'detected';
    if (window.axios) techs['Axios'] = window.axios.VERSION || 'detected';
    if (window.__APOLLO_CLIENT__) techs['Apollo GraphQL'] = 'detected';
    if (window.gsap) techs['GSAP'] = window.gsap.version;
    if (window.THREE) techs['Three.js'] = window.THREE.REVISION;
    if (window.d3) techs['D3.js'] = window.d3.version;
    if (window.Chart) techs['Chart.js'] = window.Chart.version;

    // CMS
    const wpMeta = document.querySelector('meta[name="generator"][content*="WordPress"]');
    if (wpMeta) techs['WordPress'] = wpMeta.content.match(/WordPress ([\d.]+)/)?.[1] || 'detected';
    if (window.Drupal) techs['Drupal'] = 'detected';
    const jekyllMeta = document.querySelector('meta[name="generator"][content*="Jekyll"]');
    if (jekyllMeta) techs['Jekyll'] = jekyllMeta.content.match(/Jekyll v([\d.]+)/)?.[1] || 'detected';

    // Build tools
    if (window.__vite_plugin_react_preamble_installed__) techs['Vite'] = 'detected';
    if (Object.keys(window).some(k => k.includes('webpack'))) techs['Webpack'] = 'detected';
    if (Object.keys(window).some(k => k.includes('parcel'))) techs['Parcel'] = 'detected';

    // Analytics & Tracking
    if (window.ga || window.gtag) techs['Google Analytics'] = 'detected';
    if (window.dataLayer) techs['Google Tag Manager'] = 'detected';
    if (window.fbq) techs['Facebook Pixel'] = 'detected';
    if (window._hsq) techs['HubSpot'] = 'detected';
    if (window.mixpanel) techs['Mixpanel'] = 'detected';
    if (window.amplitude) techs['Amplitude'] = 'detected';

    return techs;
  };

  try {
    // === 1. Technology Detection (First Result) ===
    const technologies = detectTechnologies();
    if (Object.keys(technologies).length) {
      log('🔧 Technologies & Versions', technologies);
    }

    // === 2. Bug Bounty Wordlist Check ===
    const bugBountyPaths = [
      // Git & Version Control
      '.git/config', '.git/HEAD', '.gitignore', '.git/logs/HEAD',
      '.svn/entries', '.hg/requires',
      
      // Backups & Archives
      'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 
      'database.sql', 'backup/', 'backups/', '.backup', 'old/',
      'backup.tar', 'www.zip', 'web.zip', 'site.zip',
      
      // Config files
      '.env', '.env.local', '.env.production', 'config.php', 
      'config.json', 'configuration.php', 'settings.php',
      'web.config', 'config.yml', 'app.config',
      
      // API endpoints
      'api/v1/users', 'api/v1/users.json', 'api/v2/users',
      'api/users', 'api/admin', 'api/config', 'api/swagger.json',
      'api/swagger', 'api/docs', 'api/v1/admin', 'api/v1/config',
      'graphql', 'api/graphql',
      
      // Admin & Debug
      'admin/', 'admin/login', 'administrator/', 'phpmyadmin/',
      'debug', 'test', 'console/', 'wp-admin/', 
      'admin/config.php', 'admin/db.php',
      
      // Docs & Info
      'robots.txt', 'sitemap.xml', 'security.txt', '.well-known/security.txt',
      'swagger.json', 'openapi.json', 'package.json', 'composer.json',
      'phpinfo.php', 'info.php',
      
      // Source maps & Debug
      'bundle.js.map', 'main.js.map', 'app.js.map', 'vendor.js.map',
      '.DS_Store', 'Thumbs.db'
    ];

    console.log('🔍 Checking common bug bounty paths...');
    const foundPaths = [];
    
    for (const path of bugBountyPaths) {
      try {
        const url = new URL(path, window.location.origin).href;
        const response = await fetch(url, { method: 'HEAD' });
        if (response.ok) {
          foundPaths.push({ path, status: response.status, url });
        }
      } catch (e) {
        // Skip errors
      }
    }
    
    if (foundPaths.length) {
      log('🎯 Found sensitive paths', foundPaths);
    }

    // === 3. JS Files & Secret Scanning ===
    const secretPatterns = {
      // AWS
      'AWS Access Key': /AKIA[0-9A-Z]{16}/g,
      'AWS Secret Key': /aws[_\-\s]?secret[_\-\s]?key['":\s]*([A-Za-z0-9/+=]{40})/gi,
      
      // GitHub
      'GitHub Token': /gh[pousr]_[A-Za-z0-9]{36}/g,
      'GitHub Classic': /ghp_[A-Za-z0-9]{36}/g,
      'GitHub OAuth': /gho_[A-Za-z0-9]{36}/g,
      'GitHub App': /ghs_[A-Za-z0-9]{36}/g,
      'GitHub Refresh': /ghr_[A-Za-z0-9]{36}/g,
      
      // GitLab
      'GitLab Token': /glpat-[A-Za-z0-9\-_]{20}/g,
      
      // Google Cloud
      'GCP API Key': /AIza[0-9A-Za-z\-_]{35}/g,
      'GCP OAuth': /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
      'GCP Service Account': /"type":\s*"service_account"/g,
	  
      // JWT
      'JWT Token': /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
      
      // API Keys (generic)
      'Generic API Key': /api[_\-\s]?key['":\s]*['"]([A-Za-z0-9_\-]{20,})['"]/gi,
      'Bearer Token': /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
      
      // Slack
      'Slack Token': /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}/g,
      'Slack Webhook': /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,10}\/B[A-Z0-9]{8,10}\/[A-Za-z0-9]{24}/g,
      
      // Stripe
      'Stripe Key': /sk_live_[0-9a-zA-Z]{24,}/g,
      'Stripe Publishable': /pk_live_[0-9a-zA-Z]{24,}/g,
      
      // Private Keys
      'Private Key': /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
      
      // Database URLs
      'Database URL': /(mongodb|postgres|mysql):\/\/[^\s'"]+/gi,
      
      // Auth Tokens
      'Authorization Header': /authorization['":\s]*['"]bearer\s+[A-Za-z0-9\-._~+/]+=*['"]/gi,
    };

    const getAllScripts = () => {
      const scripts = new Set();
      
      // Script tags
      document.querySelectorAll('script[src]').forEach(s => {
        if (s.src) scripts.add(s.src);
      });
      
      // Preload links
      document.querySelectorAll('link[rel="preload"][as="script"]').forEach(l => {
        if (l.href) scripts.add(l.href);
      });
      
      // Module preload
      document.querySelectorAll('link[rel="modulepreload"]').forEach(l => {
        if (l.href) scripts.add(l.href);
      });
      
      return Array.from(scripts);
    };

    const scanFileForSecrets = async (url) => {
      try {
        // Skip external domains that typically block CORS
        const skipDomains = [
          'analytics.tiktok.com',
          'pinterest.com',
          'googlesyndication.com',
          'bat.bing.com',
          'facebook.net',
          'googletagmanager.com',
          'go-mpulse.net',
          'doubleclick.net',
          'adsrvr.org',
          'roeyecdn.com',
          'clarity.ms',
          'pinimg.com',
          'sc-static.net',
          'dwin1.com'
        ];
        
        if (skipDomains.some(domain => url.includes(domain))) {
          return null;
        }
        
        const response = await fetch(url, { 
          mode: 'cors',
          credentials: 'omit'
        });
        
        if (!response.ok) return null;
        
        const content = await response.text();
        const found = {};
        
        for (const [name, pattern] of Object.entries(secretPatterns)) {
          const matches = [...content.matchAll(pattern)];
          if (matches.length > 0) {
            // Deduplicate and limit matches
            const uniqueMatches = [...new Set(matches.map(m => m[0]))];
            found[name] = uniqueMatches.slice(0, 5).map(m => 
              m.length > 60 ? m.substring(0, 60) + '...' : m
            );
          }
        }
        
        return Object.keys(found).length > 0 ? { url, secrets: found } : null;
      } catch (e) {
        // Silently skip CORS and network errors
        return null;
      }
    };

    console.log('🔎 Scanning JavaScript files for secrets...');
    const jsFiles = getAllScripts();
    const jsMapFiles = jsFiles
      .filter(f => !f.includes('analytics.tiktok.com') && 
                   !f.includes('pinterest.com') &&
                   !f.includes('googlesyndication.com'))
      .map(f => f + '.map')
      .concat([...document.querySelectorAll('link[href$=".js.map"]')].map(l => l.href));
    
    const allFilesToScan = [...jsFiles, ...jsMapFiles];
    
    // Filter out known external tracking/analytics domains
    const filesToScan = allFilesToScan.filter(file => {
      const url = new URL(file, window.location.origin);
      return url.origin === window.location.origin || 
             (!file.includes('analytics') && 
              !file.includes('tracking') && 
              !file.includes('ads') &&
              !file.includes('facebook') &&
              !file.includes('google') &&
              !file.includes('bing'));
    });
    
    log('📄 JavaScript files found', jsFiles);
    if (jsMapFiles.length) log('🗺️ Source maps found', jsMapFiles);
    
    const secretResults = [];
    let scanned = 0;
    const maxScans = 50; // Limit scanning to avoid too many requests
    
    for (const file of filesToScan.slice(0, maxScans)) {
      const result = await scanFileForSecrets(file);
      if (result) {
        secretResults.push(result);
      }
      scanned++;
    }
    
    console.log(`✅ Scanned ${scanned} files`);
    
    if (secretResults.length > 0) {
      // Format output properly
      const formattedResults = secretResults.map(r => ({
        file: r.url,
        secrets: r.secrets
      }));
      
      console.group('🚨 SECRETS FOUND');
      formattedResults.forEach(result => {
        console.group(`📁 ${result.file}`);
        Object.entries(result.secrets).forEach(([type, matches]) => {
          console.log(`  🔑 ${type}:`);
          matches.forEach(match => console.log(`    - ${match}`));
        });
        console.groupEnd();
      });
      console.groupEnd();
      
      results.push('SECRETS FOUND');
    } else {
      console.log('✅ No secrets found in JavaScript files');
    }

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

    // === Links Analysis ===
    const allLinks = [...document.querySelectorAll('a')]
      .map(a => a.href)
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort();

    const internalLinks = allLinks.filter(link => link.startsWith(window.location.origin));
    const externalLinks = allLinks.filter(link => 
      link.startsWith('http') && !link.startsWith(window.location.origin)
    );

    // Cloud storage buckets
    const bucketPatterns = [
      /s3[.-][\w-]*\.amazonaws\.com/i,
      /[\w-]+\.s3[.-][\w-]*\.amazonaws\.com/i,
      /storage\.googleapis\.com/i,
      /[\w-]+\.storage\.googleapis\.com/i,
      /blob\.core\.windows\.net/i,
      /[\w-]+\.blob\.core\.windows\.net/i,
      /digitaloceanspaces\.com/i,
      /[\w-]+\.digitaloceanspaces\.com/i,
      /r2\.cloudflarestorage\.com/i,
      /[\w-]+\.r2\.dev/i,
      /backblazeb2\.com/i,
      /f[\d]+\.backblazeb2\.com/i,
      /wasabisys\.com/i,
      /s3\.wasabisys\.com/i,
      /aliyuncs\.com/i,
      /cos\.[\w-]+\.myqcloud\.com/i
    ];

    const bucketLinks = allLinks.filter(link => 
      bucketPatterns.some(pattern => pattern.test(link))
    );

    if (internalLinks.length) log('Internal links on page', internalLinks);
    if (externalLinks.length) log('External links', externalLinks);
    if (bucketLinks.length) log('☁️ Cloud storage bucket links', bucketLinks);

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
