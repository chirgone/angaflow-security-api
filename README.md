# Anga Security API

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com)
[![Hono](https://img.shields.io/badge/Hono-4.7-blue.svg)](https://hono.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org)

Backend API para la plataforma de auditoría y simulación de seguridad web Anga Security.

🌐 **[api.angaflow.com](https://api.angaflow.com)** | 📚 [CONTEXT.md](./CONTEXT.md)

---

## 🏗️ Parte del Ecosistema Angaflow

```
┌─────────────────────┐
│ angaflow-security   │  Frontend
│ Astro + React       │  angaflow.com
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ angaflow-security-api│  ◄─ Este Repo
│ Hono + Workers + AI │  api.angaflow.com
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ webhook-router      │  Webhook Middleware
│ Cloudflare Worker   │  webhooks.angaflow.com
└─────────────────────┘
```

**Repositorios relacionados:**
- 🔗 [angaflow-security](https://github.com/chirgone/angaflow-security) - Frontend con Astro + React
- 🔗 [angaflow-webhook-router](https://github.com/chirgone/angaflow-webhook-router) - Router de webhooks

---

## 🚀 Características

- ✅ **RESTful API** con Hono (framework ultra-rápido)
- ✅ **Cloudflare Workers** (edge computing)
- ✅ **Workers AI** para consultor IA
- ✅ **Cloudflare Workflows** para simulación de ataques (long-running tasks)
- ✅ **Supabase** integration (PostgreSQL + Auth)
- ✅ **Mercado Pago** webhooks para procesamiento de pagos
- ✅ **JWT Authentication** con middleware
- ✅ **Admin panel** con autorización

---

## 📦 Stack Tecnológico

- **Runtime:** Cloudflare Workers
- **Framework:** Hono 4.7
- **Language:** TypeScript 5.7
- **Database:** Supabase (PostgreSQL)
- **AI:** Workers AI (Cloudflare)
- **Workflows:** Cloudflare Workflows
- **Payment:** Mercado Pago
- **Auth:** Supabase Auth (JWT)

---

## 🛠️ Instalación y Desarrollo

### Prerrequisitos

- Node.js 18+
- npm 9+
- Wrangler CLI
- Cloudflare account
- Supabase project

### Setup

```bash
# Clonar el repositorio
git clone https://github.com/chirgone/angaflow-security-api.git
cd angaflow-security-api

# Instalar dependencias
npm install

# Configurar secrets
wrangler secret put SUPABASE_URL
wrangler secret put SUPABASE_ANON_KEY
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
wrangler secret put MERCADOPAGO_ACCESS_TOKEN
wrangler secret put MERCADOPAGO_PUBLIC_KEY
wrangler secret put MERCADOPAGO_WEBHOOK_SECRET
wrangler secret put INTERNAL_WEBHOOK_SECRET

# Iniciar servidor de desarrollo
npm run dev
```

La API estará disponible en `http://localhost:8787`

---

## 📂 Estructura del Proyecto

```
angaflow-security-api/
├── src/
│   ├── index.ts                 # Entry point (Hono app)
│   ├── types.ts                 # TypeScript types
│   ├── middleware/
│   │   ├── auth.ts              # JWT authentication
│   │   └── admin.ts             # Admin authorization
│   ├── routes/
│   │   ├── health.ts            # Health check
│   │   ├── account.ts           # User accounts
│   │   ├── credits.ts           # Credit management
│   │   ├── scan.ts              # Quick scans
│   │   ├── audit.ts             # Security audits
│   │   ├── compliance.ts        # Compliance reports
│   │   ├── simulation.ts        # Attack simulations
│   │   ├── remediation.ts       # Vulnerability fixes
│   │   ├── ai.ts                # AI consultant
│   │   ├── admin.ts             # Admin endpoints
│   │   ├── leads.ts             # Lead management
│   │   └── payments.ts          # Payment webhooks
│   ├── services/
│   │   ├── audit/               # Security audit engine
│   │   ├── compliance/          # Compliance frameworks
│   │   ├── simulation/          # Attack simulation
│   │   ├── remediation/         # Remediation engine
│   │   ├── ai.ts                # Workers AI service
│   │   └── supabase.ts          # Supabase client
│   ├── workflows/
│   │   └── simulation-workflow.ts # Cloudflare Workflow
│   └── types/
│       ├── audit.ts
│       ├── compliance.ts
│       ├── simulation.ts
│       └── remediation.ts
├── database/                    # Migraciones
│   ├── migration_unique_payment_id.sql
│   └── migration_remediation_logs.sql
├── scripts/
│   └── run-migration.ts
├── wrangler.toml                # Configuración de Cloudflare
├── CONTEXT.md                   # Documentación exhaustiva
└── package.json
```

---

## 🔧 Comandos Disponibles

```bash
npm run dev            # Dev server local (localhost:8787)
npm run deploy         # Deploy a producción
wrangler tail          # Ver logs en tiempo real
wrangler secret list   # Listar secrets configurados
```

---

## 🌐 API Endpoints

### Públicos

```
GET  /api/health                      # Health check
POST /api/scan                        # Quick scan gratuito
```

### Autenticados (requieren JWT)

```
GET  /api/account                     # Info de cuenta
GET  /api/credits                     # Consultar créditos
POST /api/audit                       # Crear auditoría de seguridad
POST /api/compliance                  # Crear reporte de compliance
POST /api/simulation                  # Iniciar simulación de ataques
POST /api/remediation                 # Aplicar correcciones
POST /api/ai/chat                     # Consultar IA
```

### Admin (requieren admin role)

```
GET  /api/admin/users                 # Listar usuarios
GET  /api/admin/transactions          # Ver transacciones
GET  /api/admin/leads                 # Gestionar leads
```

### Webhooks (requieren auth interna)

```
POST /api/payments/webhooks/internal  # Webhook de pagos (post-router)
```

---

## 🔐 Autenticación

La API usa JWT de Supabase para autenticación:

```typescript
// En el cliente
const { data: { session } } = await supabase.auth.getSession()

// Request
fetch('https://api.angaflow.com/api/account', {
  headers: {
    'Authorization': `Bearer ${session.access_token}`
  }
})
```

---

## 🌍 Deployment

### Deploy a producción

```bash
# Asegúrate de que todos los secrets estén configurados
wrangler secret list

# Deploy
npm run deploy

# Verificar que funciona
curl https://api.angaflow.com/api/health
```

### Configuración de Cloudflare

El archivo `wrangler.toml` incluye:

- **Account ID:** Configurado para la cuenta de Cloudflare
- **Routes:** Custom route en `api.angaflow.com/*`
- **Bindings:** 
  - `AI` - Workers AI
  - `SIMULATION_WORKFLOW` - Cloudflare Workflow
- **Observability:** Habilitado para debugging

---

## 🔄 Cloudflare Workflows

Para simulación de ataques, usamos **Cloudflare Workflows** que permiten:

- 30 segundos de CPU por step (vs 10ms/50ms en Workers)
- State management entre steps
- Retry automático en fallos

```typescript
// src/workflows/simulation-workflow.ts
export class SimulationWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    // Cada step tiene su propio budget de 30s
    const attacks = await step.do("run-attacks", async () => {
      return await runAllAttacks()
    })
    
    const analysis = await step.do("analyze", async () => {
      return await analyzeResults(attacks)
    })
    
    return analysis
  }
}
```

---

## 🧪 Testing

```bash
# TODO: Implementar tests
npm test
```

---

## 📚 Documentación Completa

Para documentación exhaustiva sobre arquitectura, base de datos, flujos de pago, y más, ver:

📖 **[CONTEXT.md](./CONTEXT.md)** - Documento completo del ecosistema

---

## 🐛 Debugging

### Ver logs en vivo

```bash
wrangler tail
```

### Debugging local

```bash
# Dev server con hot reload
npm run dev

# Probar endpoint
curl http://localhost:8787/api/health
```

### Errores comunes

**500 Internal Server Error:**
- Verificar que todos los secrets estén configurados
- Revisar logs con `wrangler tail`
- Confirmar que Supabase está accesible

**403 Forbidden:**
- Verificar JWT en Authorization header
- Confirmar que el usuario tiene permisos

**Webhook no procesa pagos:**
- Revisar `security_payment_logs` en Supabase
- Confirmar que el webhook router está funcionando
- Verificar HMAC signature

---

## 🤝 Contribuir

Este es un proyecto privado. Para reportar issues o sugerencias, contactar a:

📧 [email protected]  
💬 WhatsApp: +52 55 5157 5041

---

## 📄 Licencia

© 2026 ANGA Mexico. Todos los derechos reservados.

---

**Made with ❤️ in Mexico** 🇲🇽
