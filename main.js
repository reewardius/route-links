(async () => {
  const results = [];

  // === Secret Patterns (defined early for use throughout script) ===
  const secretPatterns = {
    'AWS Access Key': /AKIA[0-9A-Z]{16}/g,
    'AWS Secret Key': /aws[_\-\s]?secret[_\-\s]?key['":\s]*([A-Za-z0-9/+=]{40})/gi,
    'GitHub Token': /gh[pousr]_[A-Za-z0-9]{36}/g,
    'GitHub Classic': /ghp_[A-Za-z0-9]{36}/g,
    'GitHub OAuth': /gho_[A-Za-z0-9]{36}/g,
    'GitHub App': /ghs_[A-Za-z0-9]{36}/g,
    'GitHub Refresh': /ghr_[A-Za-z0-9]{36}/g,
    'GitLab Token': /glpat-[A-Za-z0-9\-_]{20}/g,
    'GCP API Key': /AIza[0-9A-Za-z\-_]{35}/g,
    'GCP OAuth': /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    'GCP Service Account': /"type":\s*"service_account"/g,
    'JWT Token': /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
    'Generic API Key': /api[_\-\s]?key['":\s]*['"]([A-Za-z0-9_\-]{20,})['"]/gi,
    'Bearer Token': /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
    'Slack Token': /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}/g,
    'Slack Webhook': /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,10}\/B[A-Z0-9]{8,10}\/[A-Za-z0-9]{24}/g,
    'Stripe Key': /sk_live_[0-9a-zA-Z]{24,}/g,
    'Stripe Publishable': /pk_live_[0-9a-zA-Z]{24,}/g,
    'Private Key': /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    'Database URL': /(mongodb|postgres|mysql):\/\/[^\s'"]+/gi,
    'Authorization Header': /authorization['":\s]*['"]bearer\s+[A-Za-z0-9\-._~+/]+=*['"]/gi,
  };

  const log = (name, data) => {
    if (!data) return;
    
    // Better handling for objects and arrays
    if (Array.isArray(data)) {
      if (data.length === 0) return;
      console.group(`📦 ${name}`);
      data.forEach((item, idx) => {
        if (typeof item === 'object') {
          console.log(`[${idx}]`, item);
        } else {
          console.log(item);
        }
      });
      console.groupEnd();
    } else if (typeof data === 'object') {
      console.group(`📦 ${name}`);
      console.table ? console.table(data) : console.log(JSON.stringify(data, null, 2));
      console.groupEnd();
    } else {
      const output = String(data);
      if (output.trim()) {
        console.group(`📦 ${name}`);
        console.log(output);
        console.groupEnd();
      }
    }
    
    results.push(name);
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
    // === 1. Technology Detection ===
    const technologies = detectTechnologies();
    if (Object.keys(technologies).length) {
      log('🔧 Technologies & Versions', technologies);
    }

    // === 2. Security Headers Analysis ===
    console.log('🛡️ Checking security headers...');
    const checkSecurityHeaders = async () => {
      try {
        const response = await fetch(window.location.href, { method: 'HEAD' });
        const headers = {
          'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
          'X-Frame-Options': response.headers.get('X-Frame-Options'),
          'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
          'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
          'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
          'Referrer-Policy': response.headers.get('Referrer-Policy'),
          'Permissions-Policy': response.headers.get('Permissions-Policy'),
          'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin')
        };
        
        const missing = Object.entries(headers)
          .filter(([k, v]) => !v)
          .map(([k]) => k);
        
        const present = Object.entries(headers)
          .filter(([k, v]) => v)
          .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});
        
        if (Object.keys(present).length) log('🛡️ Security Headers Present', present);
        if (missing.length) log('⚠️ Missing Security Headers', missing);
      } catch (e) {
        console.log('Could not check security headers');
      }
    };
    await checkSecurityHeaders();

    // === 3. Cookie Analysis ===
    console.log('🍪 Analyzing cookies...');
    const analyzeCookies = () => {
      const cookies = document.cookie.split(';').map(c => {
        const [name, value] = c.trim().split('=');
        return { name, value: value?.substring(0, 50) };
      }).filter(c => c.name);
      
      if (cookies.length) {
        log('🍪 Cookies Found', cookies);
        
        // Check for insecure cookies (we can't access httpOnly/secure from JS, but can warn)
        console.warn('⚠️ Note: Cookies accessible from JavaScript may lack HttpOnly flag');
      }
    };
    analyzeCookies();

    // === 4. Environment Variables Exposure ===
    console.log('🔍 Checking for exposed environment variables...');
    const envVars = {};
    Object.keys(window).forEach(key => {
      if (key.match(/env|config|api_|debug|dev/i) && typeof window[key] === 'object') {
        envVars[key] = window[key];
      }
    });
    if (Object.keys(envVars).length) log('⚠️ Exposed Environment Variables', envVars);

    // === 5. Local/Session Storage Secrets ===
    console.log('💾 Scanning localStorage and sessionStorage...');
    const storageSecrets = { localStorage: {}, sessionStorage: {} };
    
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (value && (value.length > 20 || key.match(/token|key|secret|auth|api/i))) {
          storageSecrets.localStorage[key] = value.substring(0, 100) + (value.length > 100 ? '...' : '');
        }
      }
      
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        if (value && (value.length > 20 || key.match(/token|key|secret|auth|api/i))) {
          storageSecrets.sessionStorage[key] = value.substring(0, 100) + (value.length > 100 ? '...' : '');
        }
      }
      
      if (Object.keys(storageSecrets.localStorage).length || Object.keys(storageSecrets.sessionStorage).length) {
        log('💾 Storage Data Found', storageSecrets);
      }
    } catch (e) {
      console.log('Could not access storage');
    }

    // === 6. WebSocket Connection Monitoring ===
    console.log('🔌 Setting up WebSocket monitoring...');
    const originalWS = window.WebSocket;
    const wsConnections = [];
    window.WebSocket = function(...args) {
      wsConnections.push(args[0]);
      console.log('🔌 WebSocket connection detected:', args[0]);
      return new originalWS(...args);
    };
    if (wsConnections.length) log('🔌 WebSocket Connections', wsConnections);

    // === 7. Third-Party CDN Dependencies ===
    console.log('📦 Analyzing third-party dependencies...');
    const cdnLinks = [...document.querySelectorAll('script[src*="cdn"], link[href*="cdn"]')]
      .map(el => ({
        src: el.src || el.href,
        integrity: el.integrity || 'none',
        crossorigin: el.crossOrigin || 'none'
      }));
    if (cdnLinks.length) log('📦 CDN Resources', cdnLinks);

    // === 8. Metadata Extraction ===
    console.log('📝 Extracting metadata...');
    const metadata = {
      title: document.title,
      description: document.querySelector('meta[name="description"]')?.content,
      keywords: document.querySelector('meta[name="keywords"]')?.content,
      author: document.querySelector('meta[name="author"]')?.content,
      ogTitle: document.querySelector('meta[property="og:title"]')?.content,
      ogDescription: document.querySelector('meta[property="og:description"]')?.content,
      ogImage: document.querySelector('meta[property="og:image"]')?.content,
      twitterCard: document.querySelector('meta[name="twitter:card"]')?.content,
      canonical: document.querySelector('link[rel="canonical"]')?.href
    };
    
    const cleanMetadata = Object.entries(metadata)
      .filter(([k, v]) => v)
      .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});
    
    if (Object.keys(cleanMetadata).length) log('📝 Page Metadata', cleanMetadata);

    // Schema.org structured data
    const schemaScripts = [...document.querySelectorAll('script[type="application/ld+json"]')]
      .map(s => {
        try {
          return JSON.parse(s.textContent);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    if (schemaScripts.length) log('📊 Schema.org Structured Data', schemaScripts);

    // === 9. Subdomain Enumeration ===
    console.log('🌐 Extracting subdomains...');
    const subdomains = new Set();
    
    // From links
    [...document.querySelectorAll('a[href]')].forEach(a => {
      try {
        const url = new URL(a.href);
        if (url.hostname.includes('.')) {
          subdomains.add(url.hostname);
        }
      } catch {}
    });
    
    // From CSP
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content;
    if (csp) {
      const domains = csp.match(/https?:\/\/([a-z0-9\-\.]+)/gi) || [];
      domains.forEach(d => {
        try {
          subdomains.add(new URL(d).hostname);
        } catch {}
      });
    }
    
    if (subdomains.size) log('🌐 Discovered Domains', Array.from(subdomains));

    // === 10. Forms Analysis ===
    console.log('📋 Analyzing forms...');
    const forms = [...document.querySelectorAll('form')].map(f => ({
      action: f.action,
      method: f.method || 'GET',
      hasPassword: !!f.querySelector('input[type="password"]'),
      hasFile: !!f.querySelector('input[type="file"]'),
      hasCSRF: !!f.querySelector('input[name*="csrf"], input[name*="token"]'),
      inputCount: f.querySelectorAll('input, textarea, select').length
    }));
    if (forms.length) log('📋 Forms on Page', forms);

    // === 11. HTML Comments Analysis ===
    console.log('💬 Scanning HTML comments...');
    const htmlSource = document.documentElement.outerHTML;
    const comments = htmlSource.match(/<!--[\s\S]*?-->/g) || [];
    const suspiciousComments = comments.filter(c => 
      c.match(/todo|fixme|hack|bug|password|key|token|secret|api/i)
    );
    if (suspiciousComments.length) log('💬 Suspicious HTML Comments', suspiciousComments);

    // === 12. Hidden Inputs & Data Attributes ===
    console.log('🔍 Checking hidden inputs and data attributes...');
    const hiddenInputs = [...document.querySelectorAll('input[type="hidden"]')]
      .map(input => ({
        name: input.name,
        value: input.value?.substring(0, 50),
        id: input.id
      }))
      .filter(i => i.value);
    
    const dataAttributes = [...document.querySelectorAll('[data-api], [data-key], [data-token], [data-secret], [data-config]')]
      .map(el => ({
        tag: el.tagName,
        attributes: Object.keys(el.dataset).map(k => `${k}: ${el.dataset[k]?.substring(0, 50)}`)
      }));
    
    if (hiddenInputs.length) log('🔍 Hidden Inputs', hiddenInputs);
    if (dataAttributes.length) log('🔍 Suspicious Data Attributes', dataAttributes);

    // === 13. Network Timing Analysis ===
    console.log('⏱️ Analyzing network performance...');
    const resources = performance.getEntriesByType('resource');
    const slowResources = resources
      .filter(r => r.duration > 1000)
      .map(r => ({ 
        name: r.name.substring(r.name.lastIndexOf('/') + 1), 
        duration: Math.round(r.duration) + 'ms',
        size: r.transferSize ? Math.round(r.transferSize / 1024) + 'KB' : 'unknown'
      }))
      .slice(0, 10);
    
    if (slowResources.length) log('⏱️ Slow Resources (>1s)', slowResources);

    // === 14. Browser Fingerprinting Detection ===
    console.log('🎭 Checking for fingerprinting scripts...');
    const fingerprintingIndicators = {
      canvas: !!document.querySelector('canvas'),
      webgl: !!document.createElement('canvas').getContext('webgl'),
      audioContext: !!(window.AudioContext || window.webkitAudioContext),
      fonts: document.fonts?.size || 0,
      plugins: navigator.plugins?.length || 0,
      mimeTypes: navigator.mimeTypes?.length || 0
    };
    log('🎭 Fingerprinting Indicators', fingerprintingIndicators);

    // === 15. CORS Configuration Check ===
    console.log('🌍 Testing CORS configuration...');
    const testCORS = async () => {
      try {
        const response = await fetch(window.location.origin, {
          method: 'OPTIONS',
          headers: { 'Origin': 'https://evil.com' }
        });
        const corsHeaders = {
          'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
          'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
          'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
        };
        
        const present = Object.entries(corsHeaders)
          .filter(([k, v]) => v)
          .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});
        
        if (Object.keys(present).length) {
          log('🌍 CORS Configuration', present);
          if (present['Access-Control-Allow-Origin'] === '*') {
            console.warn('⚠️ WARNING: CORS allows all origins (*)');
          }
        }
      } catch (e) {
        console.log('Could not test CORS');
      }
    };
    await testCORS();

    // === 16. Bug Bounty Wordlist Check ===
    const bugBountyPaths = [
      '.git/config', '.git/HEAD', '.gitignore', '.git/logs/HEAD',
      '.svn/entries', '.hg/requires',
      'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 
      'database.sql', 'backup/', 'backups/', '.backup', 'old/',
      'backup.tar', 'www.zip', 'web.zip', 'site.zip',
      '.env', '.env.local', '.env.production', 'config.php', 
      'config.json', 'configuration.php', 'settings.php',
      'web.config', 'config.yml', 'app.config',
      'api/v1/users', 'api/v1/users.json', 'api/v2/users',
      'api/users', 'api/admin', 'api/config', 'api/swagger.json',
      'api/swagger', 'api/docs', 'api/v1/admin', 'api/v1/config',
      'graphql', 'api/graphql',
      'admin/', 'admin/login', 'administrator/', 'phpmyadmin/',
      'debug', 'test', 'console/', 'wp-admin/', 
      'admin/config.php', 'admin/db.php',
      'robots.txt', 'sitemap.xml', 'security.txt', '.well-known/security.txt',
      'swagger.json', 'openapi.json', 'package.json', 'composer.json',
      'phpinfo.php', 'info.php',
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
      } catch (e) {}
    }
    
    if (foundPaths.length) {
      log('🎯 Found Sensitive Paths', foundPaths);
    }

    // === 17. JS Files & Secret Scanning ===
    const getAllScripts = () => {
      const scripts = new Set();
      document.querySelectorAll('script[src]').forEach(s => {
        if (s.src) scripts.add(s.src);
      });
      document.querySelectorAll('link[rel="preload"][as="script"]').forEach(l => {
        if (l.href) scripts.add(l.href);
      });
      document.querySelectorAll('link[rel="modulepreload"]').forEach(l => {
        if (l.href) scripts.add(l.href);
      });
      return Array.from(scripts);
    };

    const scanFileForSecrets = async (url) => {
      try {
        const skipDomains = [
          'analytics.tiktok.com', 'pinterest.com', 'googlesyndication.com',
          'bat.bing.com', 'facebook.net', 'googletagmanager.com',
          'go-mpulse.net', 'doubleclick.net', 'adsrvr.org',
          'roeyecdn.com', 'clarity.ms', 'pinimg.com',
          'sc-static.net', 'dwin1.com'
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
            const uniqueMatches = [...new Set(matches.map(m => m[0]))];
            found[name] = uniqueMatches.slice(0, 5).map(m => 
              m.length > 60 ? m.substring(0, 60) + '...' : m
            );
          }
        }
        
        return Object.keys(found).length > 0 ? { url, secrets: found } : null;
      } catch (e) {
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
    
    log('📄 JavaScript Files Found', jsFiles);
    if (jsMapFiles.length) log('🗺️ Source Maps Found', jsMapFiles);
    
    const secretResults = [];
    let scanned = 0;
    const maxScans = 50;
    
    for (const file of filesToScan.slice(0, maxScans)) {
      const result = await scanFileForSecrets(file);
      if (result) {
        secretResults.push(result);
      }
      scanned++;
    }
    
    console.log(`✅ Scanned ${scanned} files`);
    
    if (secretResults.length > 0) {
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

    // === Framework-specific data ===
    if (window.__BUILD_MANIFEST)
      log('Next.js Pages', window.__BUILD_MANIFEST.sortedPages);
    if (window.__NEXT_DATA__)
      log('Next.js __NEXT_DATA__', window.__NEXT_DATA__);

    if (window.$nuxt?.$router?.options?.routes)
      log('Nuxt 2 Routes', window.$nuxt.$router.options.routes.map(r => r.path));
    if (window.__NUXT__) {
      log('Nuxt 3 Data', window.__NUXT__.data);
      log('Nuxt 3 Config', window.__NUXT__.config);
    }

    if (window.___loader?.pageDataDb) {
      log('Gatsby Pages', Object.keys(window.___loader.pageDataDb));
    }

    if (window.__remixManifest) log('Remix Manifest', window.__remixManifest);

    // === Links Analysis ===
    const allLinks = [...document.querySelectorAll('a')]
      .map(a => a.href)
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort();

    const internalLinks = allLinks.filter(link => link.startsWith(window.location.origin));
    const externalLinks = allLinks.filter(link => 
      link.startsWith('http') && !link.startsWith(window.location.origin)
    );

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

    if (internalLinks.length) log('Internal Links', internalLinks);
    if (externalLinks.length) log('External Links', externalLinks);
    if (bucketLinks.length) log('☁️ Cloud Storage Bucket Links', bucketLinks);

    // === Service Workers ===
    try {
      const swRegs = await navigator.serviceWorker.getRegistrations();
      if (swRegs.length) log('Service Workers', swRegs.map(r => r.scope));
    } catch {}

    // === GraphQL / Apollo ===
    if (window.__APOLLO_STATE__) log('Apollo GraphQL State', window.__APOLLO_STATE__);
    if (window.__APOLLO_CLIENT__) log('Apollo Client Detected', true);

    // === Universal Files ===
    try {
      const robots = await fetch('/robots.txt').then(r => r.text());
      if (robots) log('robots.txt', robots);
    } catch {}

    // === API Endpoint Interception ===
    console.log('🎣 Setting up API interception...');
    const apiCalls = [];
    
    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      const url = args[0];
      const options = args[1] || {};
      apiCalls.push({
        type: 'fetch',
        url: typeof url === 'string' ? url : url.url,
        method: options.method || 'GET',
        headers: options.headers,
        timestamp: new Date().toISOString()
      });
      return originalFetch.apply(this, args);
    };

    // Intercept XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    
    XMLHttpRequest.prototype.open = function(method, url) {
      this._interceptedURL = url;
      this._interceptedMethod = method;
      return originalXHROpen.apply(this, arguments);
    };
    
    XMLHttpRequest.prototype.send = function() {
      if (this._interceptedURL) {
        apiCalls.push({
          type: 'XHR',
          url: this._interceptedURL,
          method: this._interceptedMethod,
          timestamp: new Date().toISOString()
        });
      }
      return originalXHRSend.apply(this, arguments);
    };

    // Wait a bit to capture some API calls
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    if (apiCalls.length) {
      const uniqueAPIs = [...new Map(apiCalls.map(item => [item.url, item])).values()];
      log('🎣 API Calls Intercepted', uniqueAPIs);
    }

    // === Inline Scripts Analysis ===
    console.log('📜 Analyzing inline scripts...');
    const inlineScripts = [...document.querySelectorAll('script:not([src])')]
      .map((script, idx) => ({
        index: idx,
        length: script.textContent.length,
        preview: script.textContent.substring(0, 100).replace(/\s+/g, ' '),
        hasSecrets: Object.values(secretPatterns).some(pattern => {
          // Reset regex lastIndex for each test
          if (pattern.global) pattern.lastIndex = 0;
          return pattern.test(script.textContent);
        })
      }))
      .filter(s => s.length > 50);
    
    if (inlineScripts.length) log('📜 Inline Scripts', inlineScripts);

    // === Iframe Analysis ===
    console.log('🖼️ Analyzing iframes...');
    const iframes = [...document.querySelectorAll('iframe')].map(iframe => ({
      src: iframe.src,
      sandbox: iframe.sandbox.value || 'none',
      width: iframe.width,
      height: iframe.height,
      hasContentDocument: !!iframe.contentDocument
    }));
    
    if (iframes.length) log('🖼️ Iframes on Page', iframes);

    // === Performance Metrics ===
    console.log('📊 Collecting performance metrics...');
    const perfMetrics = {
      DOM_Complete: performance.timing.domComplete - performance.timing.navigationStart + 'ms',
      Page_Load: performance.timing.loadEventEnd - performance.timing.navigationStart + 'ms',
      DNS_Lookup: performance.timing.domainLookupEnd - performance.timing.domainLookupStart + 'ms',
      TCP_Connection: performance.timing.connectEnd - performance.timing.connectStart + 'ms',
      Server_Response: performance.timing.responseEnd - performance.timing.requestStart + 'ms',
      DOM_Processing: performance.timing.domInteractive - performance.timing.domLoading + 'ms'
    };
    log('📊 Performance Metrics', perfMetrics);

    // === External Resource Analysis ===
    console.log('🌐 Analyzing external resources...');
    const externalResources = resources
      .filter(r => {
        try {
          const url = new URL(r.name);
          return url.origin !== window.location.origin;
        } catch {
          return false;
        }
      })
      .reduce((acc, r) => {
        try {
          const domain = new URL(r.name).hostname;
          if (!acc[domain]) acc[domain] = [];
          acc[domain].push({
            name: r.name.split('/').pop(),
            type: r.initiatorType,
            size: r.transferSize ? Math.round(r.transferSize / 1024) + 'KB' : 'unknown'
          });
        } catch {}
        return acc;
      }, {});
    
    if (Object.keys(externalResources).length) {
      log('🌐 External Resources by Domain', externalResources);
    }

    // === Event Listeners Detection ===
    console.log('👂 Detecting event listeners...');
    const eventStats = {
      click: document.querySelectorAll('[onclick]').length,
      submit: document.querySelectorAll('[onsubmit]').length,
      load: document.querySelectorAll('[onload]').length,
      error: document.querySelectorAll('[onerror]').length,
      totalInlineHandlers: document.querySelectorAll('[onclick], [onsubmit], [onload], [onerror], [onmouseover]').length
    };
    
    if (eventStats.totalInlineHandlers > 0) {
      log('👂 Inline Event Handlers', eventStats);
    }

    // === Console Errors & Warnings ===
    console.log('⚠️ Capturing console activity...');
    const consoleMessages = { errors: [], warnings: [] };
    
    const originalError = console.error;
    const originalWarn = console.warn;
    
    console.error = function(...args) {
      consoleMessages.errors.push(args.join(' '));
      return originalError.apply(this, args);
    };
    
    console.warn = function(...args) {
      consoleMessages.warnings.push(args.join(' '));
      return originalWarn.apply(this, args);
    };

    // === SSL/TLS Certificate Info ===
    if (window.location.protocol === 'https:') {
      console.log('🔒 HTTPS connection detected');
      log('🔒 Secure Connection', 'Site uses HTTPS');
    } else {
      console.warn('⚠️ WARNING: Site uses HTTP (not secure)');
      log('⚠️ Insecure Connection', 'Site uses HTTP - not encrypted!');
    }

    // === Mixed Content Detection ===
    if (window.location.protocol === 'https:') {
      const mixedContent = [...document.querySelectorAll('script[src], link[href], img[src]')]
        .filter(el => {
          const src = el.src || el.href;
          return src && src.startsWith('http://');
        })
        .map(el => el.src || el.href);
      
      if (mixedContent.length) {
        log('⚠️ Mixed Content Warning', mixedContent);
      }
    }

    // === Accessibility Quick Check ===
    console.log('♿ Running accessibility checks...');
    const a11yIssues = {
      imagesWithoutAlt: document.querySelectorAll('img:not([alt])').length,
      linksWithoutText: [...document.querySelectorAll('a')].filter(a => !a.textContent.trim() && !a.getAttribute('aria-label')).length,
      inputsWithoutLabels: [...document.querySelectorAll('input:not([type="hidden"])')].filter(i => !i.labels || i.labels.length === 0).length,
      missingLangAttribute: !document.documentElement.hasAttribute('lang'),
      headingsOutOfOrder: false
    };

    // Check heading hierarchy
    const headings = [...document.querySelectorAll('h1, h2, h3, h4, h5, h6')];
    let lastLevel = 0;
    for (const heading of headings) {
      const level = parseInt(heading.tagName[1]);
      if (lastLevel && level > lastLevel + 1) {
        a11yIssues.headingsOutOfOrder = true;
        break;
      }
      lastLevel = level;
    }

    const a11yTotal = Object.values(a11yIssues).filter(v => v === true || v > 0).length;
    if (a11yTotal > 0) {
      log('♿ Accessibility Issues', a11yIssues);
    } else {
      log('♿ Accessibility', 'No major issues detected');
    }

    // Log captured console messages if any
    if (consoleMessages.errors.length || consoleMessages.warnings.length) {
      log('⚠️ Console Messages', consoleMessages);
    }

    // === Final Summary ===
    const summary = {
      totalScripts: jsFiles.length,
      totalLinks: allLinks.length,
      internalLinks: internalLinks.length,
      externalLinks: externalLinks.length,
      forms: forms.length,
      cookies: document.cookie.split(';').filter(c => c.trim()).length,
      storageKeys: localStorage.length + sessionStorage.length,
      technologies: Object.keys(technologies).length,
      securityIssues: results.filter(r => r.includes('SECRETS') || r.includes('Missing') || r.includes('WARNING')).length
    };

    console.log('\n' + '='.repeat(50));
    console.log('📊 SCAN SUMMARY');
    console.log('='.repeat(50));
    Object.entries(summary).forEach(([key, value]) => {
      console.log(`${key}: ${value}`);
    });
    console.log('='.repeat(50) + '\n');

    if (!results.length) {
      console.warn('⚠️ No specific framework data found. Site may use vanilla JS or data is production-minified.');
    } else {
      console.log(`✅ Analysis complete! Found data in: ${results.join(', ')}`);
    }

    console.log('\n💡 TIP: Check the console groups above for detailed results');
    console.log('🔍 To re-run: Refresh the page and paste this script again\n');

  } catch (err) {
    console.error('❌ Analysis Error:', err);
  }

})();
