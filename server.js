const express = require('express');
const cors = require('cors');
const path = require('path');
const puppeteer = require('puppeteer');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Cache implementation
const analysisCache = new Map();
const CACHE_TTL = 3600000; // 1 hora

// Rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minuto
const MAX_REQUESTS_PER_WINDOW = 10;

// Puppeteer config for production (Render.com) and local development
const puppeteerConfig = process.env.PUPPETEER_EXECUTABLE_PATH
  ? {
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-extensions',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding'
      ]
    }
  : {
      headless: process.env.HEADLESS !== 'false' ? 'new' : false, // Allow visible browser for debugging
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-blink-features=AutomationControlled',
        '--window-size=1920,1080',
        '--start-maximized'
      ],
      defaultViewport: null,
      ignoreHTTPSErrors: true,
      // Increase protocol timeout
      protocolTimeout: 120000
    };

// Configuration
const CONFIG = {
    TIMEOUTS: {
        GLOBAL: 180000, // 3 minutos máximo
        PAGE_LOAD: 60000, // 60 segundos para cargar página
        CONSENT_WAIT: 5000, // 5 segundos para detectar consent
        POST_CONSENT: 7000, // 7 segundos después del consent
        EXTRA_WAIT: 5000, // Espera adicional
        NETWORK_IDLE: 30000 // Timeout para network idle
    },
    CMP_SELECTORS: [
        { name: 'Cookiebot', selector: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll' },
        { name: 'OneTrust', selector: '#onetrust-accept-btn-handler' },
        { name: 'CookieYes', selector: '.cli-plugin-main-button' },
        { name: 'Quantcast', selector: '.qc-cmp2-summary-buttons > button[mode="primary"]' },
        { name: 'TrustArc', selector: '#truste-consent-button' },
        { name: 'Didomi', selector: '#didomi-notice-agree-button' },
        { name: 'Osano', selector: '.osano-cm-accept-all' },
        { name: 'Generic', selector: '[data-testid="uc-accept-all-button"], .fc-cta-consent, .accept-all-cookies, button[id*="accept"], button[class*="accept-all"]' }
    ],
    TRACKING_PLATFORMS: {
        // Analytics
        'google-analytics.com': 'Google Analytics',
        'analytics.google.com': 'Google Analytics 4',
        'segment.com': 'Segment CDP',
        'segment.io': 'Segment',
        'amplitude.com': 'Amplitude',
        'mixpanel.com': 'Mixpanel',
        'heap.io': 'Heap Analytics',
        'plausible.io': 'Plausible Analytics',
        'matomo.org': 'Matomo',
        'piwik.org': 'Piwik',
        
        // Advertising
        'doubleclick.net': 'Google Ads',
        'googleadservices.com': 'Google Ads',
        'googlesyndication.com': 'Google AdSense',
        'facebook.com/tr': 'Meta Pixel',
        'connect.facebook.net': 'Facebook SDK',
        'linkedin.com/px': 'LinkedIn Insight',
        'twitter.com/i/adsct': 'Twitter Pixel',
        'pinterest.com': 'Pinterest Tag',
        'snapchat.com': 'Snapchat Pixel',
        'tiktok.com': 'TikTok Pixel',
        'amazon-adsystem.com': 'Amazon Ads',
        'criteo.com': 'Criteo',
        'taboola.com': 'Taboola',
        'outbrain.com': 'Outbrain',
        
        // Experience & Testing
        'hotjar.com': 'Hotjar',
        'clarity.ms': 'Microsoft Clarity',
        'fullstory.com': 'FullStory',
        'crazyegg.com': 'Crazy Egg',
        'mouseflow.com': 'Mouseflow',
        'luckyorange.com': 'Lucky Orange',
        'optimizely.com': 'Optimizely',
        'vwo.com': 'VWO',
        'omniconvert.com': 'Omniconvert',
        
        // Customer Data & CRM
        'intercom.io': 'Intercom',
        'drift.com': 'Drift',
        'zendesk.com': 'Zendesk',
        'helpscout.net': 'Help Scout',
        'freshworks.com': 'Freshworks',
        'hubspot.com': 'HubSpot',
        'salesforce.com': 'Salesforce',
        'klaviyo.com': 'Klaviyo',
        'mailchimp.com': 'Mailchimp',
        'activecampaign.com': 'ActiveCampaign'
    }
};

// Rate limiting middleware
function rateLimitMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    if (!rateLimitMap.has(ip)) {
        rateLimitMap.set(ip, { requests: 1, windowStart: now });
        return next();
    }
    
    const userData = rateLimitMap.get(ip);
    
    if (now - userData.windowStart > RATE_LIMIT_WINDOW) {
        userData.requests = 1;
        userData.windowStart = now;
        return next();
    }
    
    if (userData.requests >= MAX_REQUESTS_PER_WINDOW) {
        return res.status(429).json({
            error: 'Too many requests',
            message: 'Please wait before making another request',
            retryAfter: Math.ceil((userData.windowStart + RATE_LIMIT_WINDOW - now) / 1000)
        });
    }
    
    userData.requests++;
    next();
}

// Simple browser pool for Render
class BrowserPool {
    constructor(size = 1) {
        this.size = size;
        this.browsers = [];
        this.available = [];
        this.creating = false;
    }
    
    async init() {
        // Don't pre-initialize browsers on Render (memory constraints)
        console.log('Browser pool ready');
    }
    
    async createBrowser() {
        try {
            this.creating = true;
            console.log('Creating new browser instance...');
            
            const browser = await puppeteer.launch(puppeteerConfig);
            
            // Test that browser is working
            const version = await browser.version();
            console.log('Browser created successfully:', version);
            
            return browser;
        } catch (error) {
            console.error('Failed to create browser:', error.message);
            throw error;
        } finally {
            this.creating = false;
        }
    }
    
    async getBrowser() {
        // Always create new browser for each request to avoid connection issues
        return await this.createBrowser();
    }
    
    async releaseBrowser(browser) {
        if (browser) {
            try {
                const pages = await browser.pages();
                for (const page of pages) {
                    try {
                        await page.close();
                    } catch (e) {
                        // Ignore page close errors
                    }
                }
                await browser.close();
            } catch (error) {
                console.error('Error closing browser:', error.message);
            }
        }
    }
    
    async closeAll() {
        for (const browser of this.browsers) {
            try {
                await browser.close();
            } catch (e) {
                // Ignore close errors
            }
        }
        this.browsers = [];
        this.available = [];
    }
}

const browserPool = new BrowserPool();

// Initialize advertising tracking object
function createAdvertisingTracking() {
    return {
        platforms: new Map(),
        serverSideIndicators: new Set(),
        cookies: new Map(),
        requests: []
    };
}

// Enhanced request analysis with CDN and location detection
async function analyzeTrackingRequest(requestUrl, method, request, report, adTracking, pageHostname) {
    const urlObj = new URL(requestUrl);
    const endpoint = urlObj.hostname;
    const pathname = urlObj.pathname;
    const params = urlObj.searchParams;
    
    // Detect CDN and server location
    const detectServerLocation = (endpoint, headers = {}) => {
        // Check for CDN headers
        if (headers['cf-ray'] || endpoint.includes('cloudflare')) return { cdn: 'Cloudflare', region: 'Global' };
        if (headers['x-served-by'] && headers['x-served-by'].includes('cache')) return { cdn: 'Fastly', region: 'Global' };
        if (headers['x-amz-cf-id']) return { cdn: 'CloudFront', region: 'Global' };
        if (headers['x-akamai']) return { cdn: 'Akamai', region: 'Global' };
        
        // Check for regional indicators in domain
        if (endpoint.includes('.eu.') || endpoint.includes('-eu-') || endpoint.includes('europe')) return { cdn: null, region: 'EU' };
        if (endpoint.includes('.asia.') || endpoint.includes('-ap-') || endpoint.includes('asia')) return { cdn: null, region: 'ASIA' };
        if (endpoint.includes('.au.') || endpoint.includes('australia')) return { cdn: null, region: 'AU' };
        
        // Default to US for most tracking services
        return { cdn: null, region: 'US' };
    };
    
    // Try to get response headers for CDN detection
    let serverInfo = { cdn: null, region: 'US' };
    try {
        const response = await request.response();
        if (response) {
            const headers = response.headers();
            serverInfo = detectServerLocation(endpoint, headers);
        }
    } catch (e) {
        serverInfo = detectServerLocation(endpoint);
    }
    
    // Check against all known platforms
    for (const [pattern, platform] of Object.entries(CONFIG.TRACKING_PLATFORMS)) {
        if (requestUrl.includes(pattern)) {
            if (!adTracking.platforms.has(platform)) {
                adTracking.platforms.set(platform, {
                    count: 0,
                    endpoints: new Set(),
                    hasServerSide: false,
                    serverInfo: serverInfo
                });
            }
            
            const platformData = adTracking.platforms.get(platform);
            platformData.count++;
            platformData.endpoints.add(endpoint);
            
            // Check if through own domain (server-side indicator)
            if (endpoint.includes(pageHostname) || (!endpoint.includes('google') && !endpoint.includes('facebook'))) {
                platformData.hasServerSide = true;
                platformData.serverInfo = { cdn: 'Own servers', region: 'Custom' };
                adTracking.serverSideIndicators.add(platform);
            }
        }
    }
    
    // Google Analytics Enhanced Detection with location
    if (requestUrl.includes('/g/collect') || requestUrl.includes('/r/collect') || 
        requestUrl.includes('google-analytics.com') || requestUrl.includes('analytics.google.com')) {
        
        const measurementId = params.get('tid') || params.get('id') || 
                            params.get('measurement_id') || extractFromPath(pathname, 'G-') || 
                            extractFromPath(pathname, 'UA-');
        
        if (measurementId) {
            // Determinar versión basada en el ID
            let version = 'Unknown';
            if (measurementId.startsWith('G-')) {
                version = 'GA4';
            } else if (measurementId.startsWith('UA-')) {
                version = 'Universal Analytics';
            }
            
            // Solo es server-side si el endpoint NO es de Google
            const isServerSide = !endpoint.includes('google-analytics.com') && 
                                !endpoint.includes('analytics.google.com') && 
                                !endpoint.includes('google.com');
            
            const existing = report.googleAnalytics.find(ga => ga.id === measurementId);
            if (!existing) {
                report.googleAnalytics.push({
                    id: measurementId,
                    version: version,
                    endpoint: endpoint,
                    type: isServerSide ? 'Server-side' : 'Client-side',
                    serverSide: isServerSide,
                    serverInfo: isServerSide ? { cdn: 'Own servers', region: 'Custom' } : serverInfo,
                    enhanced: {
                        userEngagement: params.has('engagement_time_msec'),
                        enhancedConversions: params.has('em') || params.has('ph'),
                        debugMode: params.has('debug_mode'),
                        sessionId: params.get('sid')
                    }
                });
            }
        }
    }
    
    // GTM with advanced detection
    if (requestUrl.includes('gtm.js') || requestUrl.includes('/gtm')) {
        const gtmMatch = requestUrl.match(/[?&]id=(GTM-[A-Z0-9]+)/);
        if (gtmMatch) {
            report.googleTagManager = gtmMatch[1];
            
            // Enhanced GTM configuration
            // First-party mode es cuando el script GTM.js se carga desde un subdominio propio, NO desde googletagmanager.com
            const isFirstPartyMode = !endpoint.includes('googletagmanager.com') && 
                                    !endpoint.includes('www.googletagmanager.com') &&
                                    endpoint.includes(pageHostname);
            
            report.gtmConfig = {
                id: gtmMatch[1],
                loadedFrom: endpoint,
                firstPartyMode: isFirstPartyMode,
                serverContainer: pathname.includes('/ss/'),
                customDomain: endpoint.includes(pageHostname) ? endpoint : null,
                serverInfo: endpoint.includes(pageHostname) ? { cdn: 'Own servers', region: 'Custom' } : serverInfo
            };
        }
    }
    
    // Facebook/Meta Enhanced with location
    if (requestUrl.includes('facebook.com/tr')) {
        const pixelId = params.get('id');
        const eventName = params.get('ev');
        const eventId = params.get('eid');
        
        if (!report.metaPixel) {
            report.metaPixel = {
                pixelId: pixelId,
                events: [],
                hasServerSide: false,
                hasAdvancedMatching: false,
                serverInfo: serverInfo
            };
        }
        
        if (eventName) {
            report.metaPixel.events.push({
                name: eventName,
                hasEventId: !!eventId,
                timestamp: Date.now()
            });
        }
        
        // Check for advanced matching
        if (params.has('em') || params.has('ph') || params.has('fn')) {
            report.metaPixel.hasAdvancedMatching = true;
        }
    }
    
    report.performanceMetrics.trackingRequests++;
}

// Helper function
function extractFromPath(pathname, prefix) {
    const match = pathname.match(new RegExp(`${prefix}([A-Z0-9-]+)`));
    return match ? prefix + match[1] : null;
}

// Enhanced cookie analysis
function analyzeCookie(cookie, hostname) {
    const cookieDomain = cookie.domain.replace(/^\./, '');
    const isThirdParty = !cookieDomain.includes(hostname) && !hostname.includes(cookieDomain);
    
    // Calculate expiry
    let expiry = 'Session';
    let expiryDays = 0;
    let status = 'ok';
    
    if (cookie.expires && cookie.expires !== -1) {
        const now = Date.now() / 1000;
        expiryDays = Math.floor((cookie.expires - now) / (60 * 60 * 24));
        
        if (expiryDays < 0) {
            expiry = `Expired ${Math.abs(expiryDays)} days ago`;
            status = 'expired';
        } else if (expiryDays === 0) {
            expiry = 'Expires today';
            status = 'warning';
        } else if (expiryDays > 365) {
            const years = Math.floor(expiryDays / 365);
            expiry = `${years} year${years > 1 ? 's' : ''}`;
            status = isThirdParty ? 'violation' : 'warning';
        } else if (expiryDays > 30) {
            const months = Math.floor(expiryDays / 30);
            expiry = `${months} month${months > 1 ? 's' : ''}`;
            status = isThirdParty ? 'warning' : 'ok';
        } else {
            expiry = `${expiryDays} day${expiryDays > 1 ? 's' : ''}`;
            status = 'ok';
        }
    }
    
    // Enhanced purpose detection
    const purposes = {
        analytics: ['_ga', '_gid', '_gat', '_gtm', 'gtag', 'collect'],
        advertising: ['_fbp', '_fbc', 'fr', '_gcl', '_gac', 'IDE', 'DSID', 'ads'],
        functional: ['session', 'cart', 'user', 'auth', 'login', 'token'],
        preferences: ['lang', 'locale', 'theme', 'currency', 'region'],
        security: ['csrf', 'xsrf', '__Host-', '__Secure-'],
        performance: ['_clck', '_clsk', 'perf', 'timing']
    };
    
    let purpose = 'Unknown';
    const nameLower = cookie.name.toLowerCase();
    
    for (const [category, patterns] of Object.entries(purposes)) {
        if (patterns.some(pattern => nameLower.includes(pattern.toLowerCase()))) {
            purpose = category.charAt(0).toUpperCase() + category.slice(1);
            break;
        }
    }
    
    // GDPR classification
    let gdprCategory = 'Necessary';
    if (purpose === 'Analytics' || purpose === 'Performance') {
        gdprCategory = 'Performance';
    } else if (purpose === 'Advertising') {
        gdprCategory = 'Marketing';
    } else if (purpose === 'Preferences') {
        gdprCategory = 'Functional';
    }
    
    return {
        name: cookie.name,
        domain: cookie.domain,
        path: cookie.path || '/',
        type: isThirdParty ? 'Third-party' : 'First-party',
        expiry: expiry,
        expiryDays: expiryDays,
        status: status,
        purpose: purpose,
        gdprCategory: gdprCategory,
        secure: cookie.secure || false,
        httpOnly: cookie.httpOnly || false,
        sameSite: cookie.sameSite || 'None',
        size: cookie.value ? cookie.value.length : 0
    };
}

// Main analysis function with timeout
async function analyzeWebsite(url, email = null) {
    return Promise.race([
        performAnalysis(url, email),
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Analysis timeout after 3 minutes')), CONFIG.TIMEOUTS.GLOBAL)
        )
    ]);
}

// Actual analysis implementation with better error handling
async function performAnalysis(url, email = null) {
    console.log(`🚀 Starting analysis for ${url}...`);
    if (email) console.log(`📧 Lead captured: ${email}`);
    
    let browser = null;
    let page = null;
    const adTracking = createAdvertisingTracking();
    const pageHostname = new URL(url).hostname.replace('www.', '');
    
    const report = {
        url: url,
        timestamp: new Date().toISOString(),
        domain: pageHostname,
        googleTagManager: null,
        gtmConfig: null,
        googleAnalytics: [],
        metaPixel: null,
        socialMediaPixels: {},
        analyticsTools: {},
        marketingTools: {},
        adsPlatforms: {},
        dataLayer: null,
        cookies: [],
        consentManagement: {
            detected: false,
            platform: null,
            status: 'Not detected'
        },
        performanceMetrics: {
            totalRequests: 0,
            trackingRequests: 0,
            pageLoadTime: null,
            domContentLoaded: null,
            totalTransferred: 0
        },
        securityHeaders: {},
        scoring: {
            overall: 0,
            privacy: 0,
            performance: 0,
            implementation: 0,
            security: 0,
            grade: 'N/A'
        },
        issues: [],
        recommendations: []
    };

    try {
        const startTime = Date.now();
        
        // Get browser with retry logic
        let browserAttempts = 0;
        const maxBrowserAttempts = 3;
        
        while (browserAttempts < maxBrowserAttempts) {
            try {
                browser = await browserPool.getBrowser();
                break;
            } catch (error) {
                browserAttempts++;
                console.log(`⚠️ Browser creation attempt ${browserAttempts} failed:`, error.message);
                
                if (browserAttempts >= maxBrowserAttempts) {
                    throw new Error('Failed to create browser after multiple attempts');
                }
                
                // Wait before retry
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
        
        if (!browser) {
            throw new Error('Could not create browser instance');
        }
        
        // Create page with error handling
        try {
            page = await browser.newPage();
        } catch (error) {
            console.error('Failed to create new page:', error);
            throw new Error('Browser page creation failed');
        }
        
        // Enhanced page setup with better user agent
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        await page.setViewport({ width: 1920, height: 1080 });
        
        // Set extra HTTP headers to appear more legitimate
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        });
        
        // Enable request interception for better analysis
        await page.setRequestInterception(true);
        
        // Request handler with timeout protection
        page.on('request', async (request) => {
            report.performanceMetrics.totalRequests++;
            
            try {
                const requestUrl = request.url();
                // Only analyze tracking requests, skip images/fonts
                if (!requestUrl.includes('.jpg') && !requestUrl.includes('.png') && 
                    !requestUrl.includes('.gif') && !requestUrl.includes('.woff')) {
                    await analyzeTrackingRequest(requestUrl, request.method(), request, report, adTracking, pageHostname);
                }
            } catch (error) {
                // Silent error - don't break on individual request errors
            }
            
            try {
                request.continue();
            } catch (e) {
                // Request may have been aborted, ignore
            }
        });
        
        // Response handler for size tracking
        page.on('response', (response) => {
            try {
                const headers = response.headers();
                if (headers['content-length']) {
                    report.performanceMetrics.totalTransferred += parseInt(headers['content-length']);
                }
            } catch (e) {
                // Ignore response errors
            }
        });
        
        // Performance metrics
        page.on('domcontentloaded', () => {
            report.performanceMetrics.domContentLoaded = Date.now() - startTime;
        });
        
        // Add page error handler to catch client-side errors
        page.on('pageerror', error => {
            console.log('Page error:', error.message);
        });
        
        // Handle dialog boxes (alerts, confirms, prompts)
        page.on('dialog', async dialog => {
            console.log('Dialog detected:', dialog.message());
            await dialog.accept();
        });
        
        console.log('📡 Navigating to URL...');
        
        // Try navigation with retry logic for slow sites
        let navigationResponse = null;
        
        // First attempt: Try with networkidle2 (more tolerant)
        try {
            console.log('Attempting navigation with networkidle2...');
            navigationResponse = await page.goto(url, { 
                waitUntil: 'networkidle2', 
                timeout: CONFIG.TIMEOUTS.PAGE_LOAD 
            });
            console.log('✅ Page loaded with networkidle2');
        } catch (error) {
            console.log('⚠️ First navigation attempt failed, trying with domcontentloaded...');
            
            // Second attempt: Just wait for DOM
            try {
                navigationResponse = await page.goto(url, { 
                    waitUntil: 'domcontentloaded', 
                    timeout: CONFIG.TIMEOUTS.PAGE_LOAD * 1.5
                });
                console.log('✅ Page loaded with domcontentloaded');
                
                // Wait a bit for dynamic content to load
                await page.waitForTimeout(5000);
            } catch (error2) {
                console.log('⚠️ Second navigation attempt failed, trying with load event...');
                
                // Third attempt: Just wait for load event
                try {
                    navigationResponse = await page.goto(url, { 
                        waitUntil: 'load', 
                        timeout: CONFIG.TIMEOUTS.GLOBAL - 30000 // Leave 30s for rest of analysis
                    });
                    console.log('✅ Page loaded with load event');
                    await page.waitForTimeout(3000);
                } catch (error3) {
                    // Final attempt: just navigate without waiting
                    console.log('⚠️ All standard navigation attempts failed, trying without wait...');
                    navigationResponse = await page.goto(url, { 
                        waitUntil: 'commit', 
                        timeout: 30000
                    });
                    await page.waitForTimeout(5000);
                    console.log('✅ Page navigated with basic commit');
                }
            }
        }
        
        report.performanceMetrics.pageLoadTime = Date.now() - startTime;
        
        // Check SSL
        if (navigationResponse) {
            try {
                const securityDetails = navigationResponse.securityDetails();
                report.ssl = {
                    enabled: url.startsWith('https'),
                    protocol: securityDetails?.protocol(),
                    issuer: securityDetails?.issuer()
                };
            } catch (e) {
                report.ssl = {
                    enabled: url.startsWith('https')
                };
            }
        }
        
        // Wait for dynamic content (reduced wait time)
        await page.waitForTimeout(2000);
        
        // Handle consent (with timeout protection)
        try {
            const consentResult = await Promise.race([
                handleConsentBanner(page, CONFIG),
                new Promise(resolve => setTimeout(() => resolve({
                    detected: false,
                    platform: null,
                    status: 'Timeout detecting consent'
                }), CONFIG.TIMEOUTS.CONSENT_WAIT * 2))
            ]);
            report.consentManagement = consentResult;
        } catch (error) {
            console.log('⚠️ Consent detection error:', error.message);
        }
        
        // Wait for post-consent loading (reduced wait)
        await page.waitForTimeout(Math.min(CONFIG.TIMEOUTS.POST_CONSENT, 5000));
        
        // Collect all data (with timeout protection)
        try {
            await Promise.race([
                collectPageData(page, report, url),
                new Promise((resolve) => setTimeout(resolve, 20000)) // 20s max for data collection
            ]);
        } catch (error) {
            console.log('⚠️ Data collection error:', error.message);
        }
        
        // Process advertising tracking with corrected server-side detection
        processAdvertisingData(report, adTracking, pageHostname);
        
        // Calculate comprehensive scoring
        calculateEnhancedScoring(report, pageHostname);
        
        // Generate recommendations
        generateSmartRecommendations(report);
        
        console.log('✅ Analysis completed successfully');
        return report;

    } catch (error) {
        console.error('❌ Analysis error:', error);
        
        // Return partial report even on error
        if (report.performanceMetrics.totalRequests > 0) {
            // We got some data, return it
            calculateEnhancedScoring(report, pageHostname);
            generateSmartRecommendations(report);
            report.error = error.message;
            return report;
        }
        
        throw error;
    } finally {
        // Clean up resources
        if (page) {
            try {
                await page.close();
            } catch (e) {
                console.log('Error closing page:', e.message);
            }
        }
        if (browser) {
            await browserPool.releaseBrowser(browser);
        }
    }
}

// Enhanced consent handling with better timeout
async function handleConsentBanner(page, config) {
    const result = {
        detected: false,
        platform: null,
        status: 'Not detected',
        acceptedAt: null
    };
    
    // Try each CMP selector
    for (const cmp of config.CMP_SELECTORS) {
        try {
            const element = await page.$(cmp.selector);
            
            if (element) {
                result.detected = true;
                result.platform = cmp.name;
                
                // Try to click the accept button
                try {
                    await element.click();
                    result.status = `Accepted (${cmp.name})`;
                    result.acceptedAt = new Date().toISOString();
                    console.log(`✅ Consent accepted via ${cmp.name}`);
                    
                    // Wait for consent to process
                    await page.waitForTimeout(2000);
                } catch (clickError) {
                    console.log(`⚠️ Could not click consent for ${cmp.name}`);
                    result.status = `Detected but not clicked (${cmp.name})`;
                }
                
                return result;
            }
        } catch (error) {
            // Continue trying other selectors
        }
    }
    
    // Also check for presence in a more general way
    try {
        const hasConsentText = await page.evaluate(() => {
            const text = document.body.innerText.toLowerCase();
            return text.includes('cookie') && (text.includes('accept') || text.includes('consent'));
        });
        
        if (hasConsentText) {
            result.detected = true;
            result.platform = 'Unknown CMP';
            result.status = 'Detected but not interacted';
        }
    } catch (e) {
        // Silent fail
    }
    
    return result;
}

// Collect comprehensive page data with timeout protection
async function collectPageData(page, report, url) {
    try {
        // DataLayer detection
        report.dataLayer = await page.evaluate(() => {
            if (typeof window.dataLayer !== 'undefined') {
                if (Array.isArray(window.dataLayer)) {
                    // Extract key events
                    const events = window.dataLayer
                        .filter(item => item && item.event)
                        .map(item => item.event);
                    
                    return {
                        exists: true,
                        size: window.dataLayer.length,
                        events: [...new Set(events)].slice(0, 20), // Limit events to 20
                        hasEcommerce: window.dataLayer.some(item => item.ecommerce),
                        hasUserId: window.dataLayer.some(item => item.userId)
                    };
                }
                return { exists: true, type: 'non-array' };
            }
            return { exists: false };
        }).catch(e => ({ exists: false, error: e.message }));
        
        // Enhanced cookie collection
        try {
            const cookies = await page.cookies();
            const hostname = new URL(url).hostname.replace('www.', '');
            
            report.cookies = cookies.map(cookie => analyzeCookie(cookie, hostname));
        } catch (e) {
            console.log('Cookie collection error:', e.message);
            report.cookies = [];
        }
        
        // JavaScript variables detection
        report.jsTracking = await page.evaluate(() => {
            const tracking = {};
            
            // Google Analytics
            if (typeof gtag !== 'undefined') tracking.gtag = true;
            if (typeof ga !== 'undefined') tracking.ga = true;
            if (typeof _gaq !== 'undefined') tracking._gaq = true;
            
            // Facebook
            if (typeof fbq !== 'undefined') tracking.fbq = true;
            if (typeof FB !== 'undefined') tracking.FB = true;
            
            // Others
            if (typeof Intercom !== 'undefined') tracking.Intercom = true;
            if (typeof analytics !== 'undefined') tracking.analytics = true;
            if (typeof mixpanel !== 'undefined') tracking.mixpanel = true;
            if (typeof amplitude !== 'undefined') tracking.amplitude = true;
            if (typeof heap !== 'undefined') tracking.heap = true;
            
            return tracking;
        }).catch(e => ({}));
        
    } catch (error) {
        console.error('Data collection error:', error);
    }
}

// Process advertising data with better server-side detection
function processAdvertisingData(report, adTracking, pageHostname) {
    // Check if we have server-side tracking based on Google Analytics endpoints
    let hasRealServerSide = false;
    let serverSidePlatforms = [];
    
    // Check Google Analytics for real server-side (non-Google endpoints only)
    if (report.googleAnalytics && report.googleAnalytics.length > 0) {
        report.googleAnalytics.forEach(ga => {
            // Solo es server-side si el endpoint NO es de Google
            if (ga.endpoint && 
                !ga.endpoint.includes('google-analytics.com') && 
                !ga.endpoint.includes('analytics.google.com') && 
                !ga.endpoint.includes('google.com')) {
                hasRealServerSide = true;
                ga.serverSide = true;
                ga.type = 'Server-side';
                
                // Check if it's using a subdomain of the main domain
                const mainDomain = pageHostname.replace('www.', '');
                if (ga.endpoint.includes(mainDomain)) {
                    ga.usesOwnSubdomain = true;
                }
                
                if (!serverSidePlatforms.includes('Google Analytics')) {
                    serverSidePlatforms.push('Google Analytics');
                }
            } else {
                // Asegurar que se marca como client-side si es endpoint de Google
                ga.serverSide = false;
                ga.type = 'Client-side';
                ga.usesOwnSubdomain = false;
            }
        });
    }
    
    // Check GTM configuration for custom domain (pero NO es first-party mode, eso es diferente)
    if (report.gtmConfig && report.gtmConfig.customDomain) {
        hasRealServerSide = true;
        if (!serverSidePlatforms.includes('Google Tag Manager')) {
            serverSidePlatforms.push('Google Tag Manager');
        }
    }
    
    // Normalize and deduplicate platforms
    const normalizedPlatforms = new Map();
    
    // Helper to normalize platform names
    const normalizePlatformName = (name) => {
        const normalizations = {
            'Facebook SDK': 'Meta Pixel',
            'Facebook': 'Meta Pixel',
            'Meta Pixel': 'Meta Pixel',
            'Google Analytics 4': 'Google Analytics',
            'Google Analytics': 'Google Analytics',
            'Google Ads': 'Google Ads',
            'Google AdSense': 'Google AdSense',
            'LinkedIn Insight': 'LinkedIn',
            'LinkedIn': 'LinkedIn',
            'Twitter Pixel': 'Twitter',
            'Twitter': 'Twitter'
        };
        
        return normalizations[name] || name;
    };
    
    // Process detected platforms
    for (const [platform, data] of adTracking.platforms) {
        const normalizedName = normalizePlatformName(platform);
        
        // Skip DoubleClick as it's Google's infrastructure
        if (normalizedName.includes('DoubleClick') || normalizedName.includes('doubleclick')) {
            continue;
        }
        
        if (!normalizedPlatforms.has(normalizedName)) {
            normalizedPlatforms.set(normalizedName, {
                detected: true,
                requestCount: 0,
                hasServerSide: false,
                endpoints: new Set()
            });
        }
        
        const platformData = normalizedPlatforms.get(normalizedName);
        platformData.requestCount += data.count;
        platformData.hasServerSide = platformData.hasServerSide || data.hasServerSide;
        data.endpoints.forEach(endpoint => platformData.endpoints.add(endpoint));
    }
    
    // Compile into report categories
    for (const [platform, data] of normalizedPlatforms) {
        const category = getToolCategory(platform);
        
        if (!report[category]) {
            report[category] = {};
        }
        
        // Don't duplicate Google Analytics if already processed
        if (platform === 'Google Analytics' && report.googleAnalytics.length > 0) {
            continue;
        }
        
        report[category][platform] = {
            detected: true,
            requestCount: data.requestCount,
            hasServerSide: data.hasServerSide,
            endpoints: Array.from(data.endpoints)
        };
    }
    
    // Update server-side tracking summary based on real detection
    if (hasRealServerSide) {
        report.serverSideTracking = {
            detected: true,
            platforms: serverSidePlatforms,
            confidence: 100
        };
    }
}

// Tool categorization
function getToolCategory(platform) {
    const categories = {
        analytics: ['Google Analytics', 'Segment', 'Amplitude', 'Mixpanel', 'Heap', 'Plausible', 'Matomo'],
        advertising: ['Google Ads', 'Meta Pixel', 'LinkedIn', 'Twitter', 'Pinterest', 'TikTok', 'Amazon'],
        experience: ['Hotjar', 'Microsoft Clarity', 'FullStory', 'Crazy Egg'],
        marketing: ['HubSpot', 'Mailchimp', 'Klaviyo', 'ActiveCampaign'],
        customerData: ['Intercom', 'Drift', 'Zendesk', 'Salesforce']
    };
    
    for (const [category, tools] of Object.entries(categories)) {
        if (tools.some(tool => platform.includes(tool))) {
            return category === 'analytics' ? 'analyticsTools' :
                   category === 'advertising' ? 'adsPlatforms' :
                   category === 'experience' ? 'analyticsTools' :
                   category === 'marketing' ? 'marketingTools' :
                   'otherServices';
        }
    }
    return 'otherServices';
}

// Enhanced scoring calculation
function calculateEnhancedScoring(report, pageHostname) {
    let privacyScore = 100;
    let performanceScore = 100;
    let implementationScore = 100;
    let securityScore = 100;
    const issues = [];
    
    // Privacy scoring
    const totalCookies = report.cookies.length;
    const thirdPartyCookies = report.cookies.filter(c => c.type === 'Third-party').length;
    const longLivedCookies = report.cookies.filter(c => c.expiryDays > 365).length;
    
    if (thirdPartyCookies > 0) {
        privacyScore -= Math.min(thirdPartyCookies * 5, 40);
        issues.push({
            severity: 'high',
            category: 'privacy',
            title: `${thirdPartyCookies} third-party cookies detected`,
            description: 'Third-party cookies can track users across websites',
            impact: 'Privacy risk and potential GDPR compliance issues'
        });
    }
    
    if (longLivedCookies > 0) {
        privacyScore -= Math.min(longLivedCookies * 3, 20);
        issues.push({
            severity: 'medium',
            category: 'privacy',
            title: `${longLivedCookies} cookies with >1 year expiry`,
            description: 'Long-lived cookies may violate privacy regulations',
            impact: 'GDPR recommends shorter cookie lifespans'
        });
    }
    
    // Performance scoring
    const loadTime = report.performanceMetrics.pageLoadTime;
    if (loadTime > 5000) performanceScore -= 20;
    if (loadTime > 10000) performanceScore -= 30;
    
    if (report.performanceMetrics.trackingRequests > 50) {
        performanceScore -= 25;
        issues.push({
            severity: 'high',
            category: 'performance',
            title: 'Excessive tracking requests',
            description: `${report.performanceMetrics.trackingRequests} tracking calls detected`,
            impact: 'Significant performance impact'
        });
    }
    
    // Implementation scoring
    if (report.googleTagManager) {
        implementationScore += 10;
        
        if (report.gtmConfig && report.gtmConfig.firstPartyMode) {
            implementationScore += 20;
            privacyScore += 10;
        }
    }
    
    if (report.serverSideTracking && report.serverSideTracking.detected) {
        implementationScore += 25;
        privacyScore += 15;
    }
    
    // Security scoring
    if (!report.ssl || !report.ssl.enabled) {
        securityScore -= 50;
        issues.push({
            severity: 'critical',
            category: 'security',
            title: 'No HTTPS encryption',
            description: 'Site not using SSL/TLS',
            impact: 'Critical security vulnerability'
        });
    }
    
    if (report.securityHeaders) {
        if (report.securityHeaders.csp === 'Missing') securityScore -= 10;
        if (report.securityHeaders.hsts === 'Missing') securityScore -= 10;
        if (report.securityHeaders.xFrameOptions === 'Missing') securityScore -= 5;
    }
    
    // Consent management bonus
    if (report.consentManagement.detected) {
        privacyScore += 10;
        implementationScore += 10;
    }
    
    // Normalize scores
    privacyScore = Math.max(0, Math.min(100, privacyScore));
    performanceScore = Math.max(0, Math.min(100, performanceScore));
    implementationScore = Math.max(0, Math.min(100, implementationScore));
    securityScore = Math.max(0, Math.min(100, securityScore));
    
    // Calculate overall with weights
    const overallScore = Math.round(
        (privacyScore * 0.3) + 
        (performanceScore * 0.25) + 
        (implementationScore * 0.25) +
        (securityScore * 0.2)
    );
    
    // Grade calculation
    const grade = 
        overallScore >= 90 ? 'A+' :
        overallScore >= 85 ? 'A' :
        overallScore >= 80 ? 'A-' :
        overallScore >= 75 ? 'B+' :
        overallScore >= 70 ? 'B' :
        overallScore >= 65 ? 'B-' :
        overallScore >= 60 ? 'C+' :
        overallScore >= 55 ? 'C' :
        overallScore >= 50 ? 'C-' :
        overallScore >= 40 ? 'D' : 'F';
    
    report.scoring = {
        overall: overallScore,
        privacy: Math.round(privacyScore),
        performance: Math.round(performanceScore),
        implementation: Math.round(implementationScore),
        security: Math.round(securityScore),
        grade: grade
    };
    
    report.issues = issues;
}

// Generate smart recommendations with corrected logic
function generateSmartRecommendations(report) {
    const recommendations = [];
    
    // Check what's already implemented
    const pageHostname = report.domain;
    
    // Check if GA is using a subdomain of the main domain (real server-side)
    const hasServerSideGAWithSubdomain = report.googleAnalytics && 
        report.googleAnalytics.some(ga => {
            if (!ga.serverSide || !ga.endpoint) return false;
            // Check if endpoint is a subdomain of the main domain
            const mainDomain = pageHostname.replace('www.', '');
            return ga.endpoint.includes(mainDomain) && ga.endpoint !== mainDomain;
        });
    
    const hasServerSideGA = report.googleAnalytics && 
        report.googleAnalytics.some(ga => ga.serverSide && ga.endpoint && 
            !ga.endpoint.includes('google-analytics.com') && 
            !ga.endpoint.includes('analytics.google.com') && 
            !ga.endpoint.includes('google.com'));
    
    const hasCustomDomain = report.gtmConfig && report.gtmConfig.customDomain;
    
    // CORRECCIÓN: First-party mode es cuando GTM.js se carga desde subdominio propio
    const hasGTMFirstParty = report.gtmConfig && report.gtmConfig.firstPartyMode;
    
    const hasGTM = report.googleTagManager !== null;
    
    // 1. Custom subdomain for server GTM container
    if (hasGTM) {
        const isImplemented = hasCustomDomain || hasServerSideGAWithSubdomain;
        recommendations.push({
            priority: 'critical',
            title: 'Set up custom subdomain for server GTM container',
            categories: ['Advertising', 'Cookies', 'Analytics'],
            scoreImprovement: 31,
            description: isImplemented ? 
                "Your tracking is using a custom subdomain, ensuring first-party cookies are set correctly." :
                "We've detected that you're not using own subdomain for your sGTM container. As a result, cookies may not be set correctly, potentially impacting your tracking accuracy.",
            benefits: [
                'Set first-party cookies',
                'Avoid cookie lifespan restrictions',
                'Improve tracking precision'
            ],
            effort: 'medium',
            impact: 'high',
            howTo: 'Use a subdomain like tracking.yourdomain.com for your GTM server container',
            implemented: isImplemented
        });
    }

    // 2. Google Analytics 4 server-side tracking
    if (report.googleAnalytics && report.googleAnalytics.length > 0) {
        const isImplemented = hasServerSideGA;
        recommendations.push({
            priority: 'high',
            title: 'Implement Google Analytics 4 server-side tracking',
            categories: ['Analytics'],
            scoreImprovement: 17,
            description: isImplemented ?
                "Google Analytics 4 with server-side tracking is active, providing better data quality and privacy compliance." :
                "We've detected a client-side Google Analytics 4 script. While this setup works, client-side tracking is more vulnerable to ad blockers, cookie restrictions, and browser privacy settings issues.",
            benefits: [
                'Ensure complete and precise tracking, even with ad blockers in use',
                'Align with privacy regulations such as GDPR',
                'Reduce tracking disruptions'
            ],
            effort: 'high',
            impact: 'high',
            howTo: 'Set up GA4 server-side tracking through GTM Server Container',
            implemented: isImplemented
        });
    }

    // 3. GTM First-Party Mode - CORRECTED LOGIC
    if (hasGTM) {
        const isImplemented = hasGTMFirstParty;
        recommendations.push({
            priority: 'high',
            title: 'Enable GTM First-Party Mode',
            categories: ['Analytics', 'Privacy'],
            scoreImprovement: 15,
            description: isImplemented ?
                "GTM is loading from your own domain, protecting against ad blockers." :
                "Your GTM container is loading from googletagmanager.com. This makes it vulnerable to ad blockers and can result in 15-30% data loss.",
            benefits: [
                'Avoid being blocked by ad blockers',
                'Improve data collection accuracy',
                'Ensure consistent tracking across all browsers'
            ],
            effort: 'low',
            impact: 'high',
            howTo: 'Configure GTM to load from your own domain using a custom loader script that serves gtm.js from your subdomain',
            implemented: isImplemented
        });
    }

    // 4. Avoid negative impact of ad blockers - Requires manual review
    if (hasGTM) {
        // Almost no one has this - requires proxy configuration
        const isImplemented = false; // Default to not implemented
        const needsManualReview = true; // Always needs review for this complex setup
        
        recommendations.push({
            priority: 'high',
            title: 'Avoid negative impact of ad blockers',
            categories: ['Advertising', 'Analytics'],
            scoreImprovement: 13,
            description: needsManualReview ?
                "⚠️ This requires a personalized consultation. Ad blockers can interfere with your tracking. Contact us for a custom assessment of your setup and implementation of a reverse proxy solution." :
                "Your tracking setup is protected against ad blockers through reverse proxy configuration.",
            benefits: [
                'Get precise tracking, even with ad blockers in use',
                'Have cleaner view of user behavior and campaign performance',
                'Maintain full control over your analytics setup and data integrity'
            ],
            effort: 'high',
            impact: 'high',
            howTo: needsManualReview ? 'Schedule a consultation for custom reverse proxy setup' : 'Implement a reverse proxy for tracking endpoints',
            implemented: isImplemented,
            requiresConsultation: needsManualReview
        });
    }

    // 5. Switch to web & server-side tracking for Meta
    if (report.metaPixel) {
        const isImplemented = report.metaPixel.hasServerSide;
        recommendations.push({
            priority: 'medium',
            title: 'Switch to web & server-side tracking for Meta',
            categories: ['Advertising'],
            scoreImprovement: 8,
            description: isImplemented ?
                "Meta tracking is configured with both web and server-side implementation for optimal performance." :
                "You're using client-side tracking for Meta. Meta recommends a hybrid tracking method – combining both web and server-side tracking.",
            benefits: [
                'Combine web and server-side tracking for more reliable results',
                'Capture a fuller picture of user interactions',
                "Stay aligned with Meta's recommended tracking setup"
            ],
            effort: 'medium',
            impact: 'high',
            howTo: 'Implement Meta Conversions API alongside your existing Pixel',
            implemented: isImplemented
        });
    }

    // 6. Move to Google Ads server-side tracking - DEFAULT NOT IMPLEMENTED
    const hasGoogleAds = (report.adsPlatforms && report.adsPlatforms['Google Ads']) ||
                         (report.jsTracking && (report.jsTracking._gcl || report.jsTracking._gac));
    
    if (hasGoogleAds) {
        const isImplemented = false; // ALWAYS false as almost no one has this
        const needsManualReview = true;
        
        recommendations.push({
            priority: 'medium',
            title: 'Move to Google Ads server-side tracking',
            categories: ['Advertising'],
            scoreImprovement: 7,
            description: needsManualReview ?
                "⚠️ This requires a personalized consultation. Server-side Google Ads tracking requires complex setup with Enhanced Conversions API. Contact us for implementation guidance." :
                "Google Ads is configured with server-side tracking for improved accuracy.",
            benefits: [
                'Avoid disruptions caused by ad blockers and browser privacy settings',
                'Ensure better alignment with privacy regulations',
                'Improve overall tracking efficiency'
            ],
            effort: 'very high',
            impact: 'high',
            howTo: needsManualReview ? 'Schedule a consultation for Enhanced Conversions setup' : 'Configure Google Ads Enhanced Conversions through server-side GTM',
            implemented: isImplemented,
            requiresConsultation: needsManualReview
        });
    }

    // 7. Consent Management Platform (always check)
    const hasConsent = report.consentManagement && report.consentManagement.detected;
    recommendations.push({
        priority: 'critical',
        title: 'Implement Consent Management Platform',
        categories: ['Privacy', 'GDPR'],
        scoreImprovement: 20,
        description: hasConsent ?
            `Cookie consent is implemented using ${report.consentManagement.platform}.` :
            "No consent management platform detected. GDPR requires explicit user consent for tracking cookies.",
        benefits: [
            'Ensure GDPR compliance',
            'Build trust with your users',
            'Avoid potential legal penalties'
        ],
        effort: 'medium',
        impact: 'high',
        howTo: 'Implement a CMP like Cookiebot, OneTrust, or similar',
        implemented: hasConsent
    });

    // Sort all recommendations by score improvement
    recommendations.sort((a, b) => (b.scoreImprovement || 0) - (a.scoreImprovement || 0));
    
    // Don't limit - return all recommendations with their implementation status
    report.recommendations = recommendations;
}

// API Endpoints
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        service: 'Website Tracking Analyzer Pro',
        version: '2.0.1',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development'
    });
});

app.post('/api/analyze', rateLimitMiddleware, async (req, res) => {
    const { url, email } = req.body;
    
    if (!url) {
        return res.status(400).json({ 
            error: 'URL is required',
            message: 'Please provide a URL to analyze'
        });
    }
    
    // Save lead if email provided
    if (email) {
        const lead = {
            email: email,
            url: url,
            timestamp: new Date().toISOString(),
            ip: req.ip || req.connection.remoteAddress
        };
        
        // Create header if file doesn't exist
        if (!fs.existsSync('leads.csv')) {
            fs.writeFileSync('leads.csv', 'email,url,timestamp,ip\n');
        }
        
        // Add the lead
        const csvLine = `${lead.email},${lead.url},${lead.timestamp},${lead.ip}\n`;
        fs.appendFileSync('leads.csv', csvLine);
        
        console.log('📧 New lead captured:', lead.email);
    }
    
    try {
        new URL(url);
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            throw new Error('Invalid protocol');
        }
    } catch (error) {
        return res.status(400).json({ 
            error: 'Invalid URL',
            message: 'Please provide a valid URL starting with http:// or https://'
        });
    }
    
    // Server-side cache with shorter TTL
    const cacheKey = crypto.createHash('md5').update(url.toLowerCase()).digest('hex');
    const CACHE_TTL_SHORT = 600000; // 10 minutes for server cache
    
    // Check cache only for very recent analyses
    if (analysisCache.has(cacheKey)) {
        const cached = analysisCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_TTL_SHORT) {
            console.log('📦 Returning recent cached result');
            return res.json({ 
                ...cached.data, 
                fromCache: true,
                cachedAt: new Date(cached.timestamp).toISOString()
            });
        } else {
            // Remove stale cache
            analysisCache.delete(cacheKey);
        }
    }
    
    console.log(`\n🔍 New analysis request for: ${url}`);
    console.log(`🕐 Started at: ${new Date().toLocaleString()}`);
    
    try {
        const report = await analyzeWebsite(url, email);
        
        // Cache the result
        analysisCache.set(cacheKey, {
            timestamp: Date.now(),
            data: report
        });
        
        // Clean old cache entries if too many
        if (analysisCache.size > 50) {
            const oldestKey = analysisCache.keys().next().value;
            analysisCache.delete(oldestKey);
        }
        
        console.log(`✅ Analysis completed`);
        console.log(`   Score: ${report.scoring.overall}/100 (${report.scoring.grade})`);
        console.log(`   Cookies: ${report.cookies.length}`);
        console.log(`   Tracking platforms: ${report.performanceMetrics.trackingRequests}`);
        
        res.json(report);
        
    } catch (error) {
        console.error('❌ Analysis failed:', error);
        
        // Provide more helpful error messages
        let userMessage = 'Analysis failed. Please try again.';
        
        if (error.message.includes('timeout')) {
            userMessage = 'The website took too long to load. Please try again.';
        } else if (error.message.includes('Navigation')) {
            userMessage = 'Could not navigate to the website. Please check if the URL is correct and accessible.';
        } else if (error.message.includes('net::')) {
            userMessage = 'Network error. Please check your internet connection and try again.';
        }
        
        res.status(500).json({ 
            error: 'Analysis failed',
            message: userMessage,
            technicalDetails: process.env.NODE_ENV === 'development' ? error.message : undefined,
            suggestion: 'Please verify the URL is accessible and try again'
        });
    }
});

// Export report endpoint
app.post('/api/export', (req, res) => {
    const { data, format = 'json' } = req.body;
    
    if (!data) {
        return res.status(400).json({ error: 'No data to export' });
    }
    
    if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename="tracking-analysis.json"');
        res.send(JSON.stringify(data, null, 2));
    } else if (format === 'csv') {
        // CSV export for cookies
        const csv = convertToCSV(data.cookies);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="cookies-analysis.csv"');
        res.send(csv);
    } else {
        res.status(400).json({ error: 'Unsupported format' });
    }
});

// CSV converter
function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvHeaders = headers.join(',');
    
    const csvRows = data.map(row => {
        return headers.map(header => {
            const value = row[header];
            return typeof value === 'string' && value.includes(',') 
                ? `"${value}"` 
                : value;
        }).join(',');
    });
    
    return [csvHeaders, ...csvRows].join('\n');
}

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Not found',
        message: `Route ${req.path} does not exist`
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('🔥 Server error:', err);
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'An error occurred'
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔴 SIGTERM received, shutting down gracefully...');
    await browserPool.closeAll();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🔴 SIGINT received, shutting down gracefully...');
    await browserPool.closeAll();
    process.exit(0);
});

// Initialize and start server
async function startServer() {
    try {
        await browserPool.init();
        
        app.listen(PORT, () => {
            console.log('╔══════════════════════════════════════════════╗');
            console.log('║   🚀 Website Tracking Analyzer Pro v2.0.1   ║');
            console.log('╠══════════════════════════════════════════════╣');
            console.log(`║   ✅ Server:     http://localhost:${PORT}       ║`);
            console.log(`║   📊 API:        /api/analyze                ║`);
            console.log(`║   💾 Export:     /api/export                 ║`);
            console.log(`║   🏥 Health:     /api/health                 ║`);
            console.log('╠══════════════════════════════════════════════╣');
            console.log('║   Environment: ' + (process.env.NODE_ENV || 'development').padEnd(30) + '║');
            console.log('║   Platform:    ' + (process.env.RENDER ? 'Render.com' : 'Local').padEnd(30) + '║');
            console.log('╚══════════════════════════════════════════════╝');
            console.log('\nReady to analyze websites...\n');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();