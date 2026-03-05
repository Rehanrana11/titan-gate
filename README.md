# Hireinstein

AI Visibility Tracker. See how GPT, Claude, Gemini, and Grok rank your brand.

## Quick Start

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env.local
# Edit .env.local with your API keys

# Start development
npm run dev
```

The web app runs at `http://localhost:3000` and the API at `http://localhost:3001`.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `OPENAI_API_KEY` | Yes | OpenAI API key for GPT ranking |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude ranking |
| `GOOGLE_API_KEY` | No | Google AI API key for Gemini ranking |
| `XAI_API_KEY` | No | xAI API key for Grok ranking |
| `REDIS_URL` | Yes | Redis connection for session storage |
| `STRIPE_SECRET_KEY` | Yes | Stripe secret key for billing |
| `STRIPE_PUBLISHABLE_KEY` | Yes | Stripe publishable key |
| `STRIPE_WEBHOOK_SECRET` | Yes | Stripe webhook signing secret |
| `NEXT_PUBLIC_API_URL` | Yes | API URL (default: `http://localhost:3001`) |
| `MOCK_AI` | No | Set to `true` to use mock AI responses |
| `MOCK_SCENARIO` | No | Mock scenario preset (see below) |

## Mock Mode

For development without API keys, enable mock mode:

```
MOCK_AI=true
MOCK_SCENARIO=realistic
```

Available scenarios:

| Scenario | Behavior |
|---|---|
| `realistic` | Mixed outcomes with configurable success rates per model |
| `allSuccess` | All 4 models return successful responses |
| `partialFailure` | 2 models succeed, 2 return 5xx errors |
| `allServerError` | All models return 5xx errors |
| `rateLimited` | First model returns 429, remaining calls abort |
| `allTimeout` | All models exceed 8s timeout |

## Project Structure

```
hireinstein/
  apps/
    web/                    # Next.js frontend
      app/                  # Pages (login, signup, dashboard, privacy)
      components/           # UI components
        home/               # Homepage sections
        layout/             # Navbar, Footer
        ui/                 # Button, Card, Icons
      hooks/                # useSnapshot custom hook
      e2e/                  # Playwright E2E tests
    api/                    # Express backend
      src/
        lib/                # mockAI service
        middleware/          # Auth middleware
        routes/             # API routes (auth, ranking, billing)
        services/           # Business logic (auth, ranking, stripe)
  docs/
    api.yaml                # OpenAPI 3.0 spec
    scoring-methodology.md  # Public scoring formula
  scripts/
    doctor/                 # Build health checks
```

## API

The ranking API accepts a domain and query, then queries up to 4 AI models in parallel.

```
POST /api/v1/rank
POST /api/v1/snapshot
```

Request:
```json
{
  "domain": "stripe.com",
  "query": "best payment processor"
}
```

Response:
```json
{
  "domain": "stripe.com",
  "query": "best payment processor",
  "aiVisibilityScore": 72,
  "confidenceInterval": { "low": 65, "high": 79, "level": "high" },
  "rankings": [...],
  "totalResponseTimeMs": 2340
}
```

Full API documentation: `docs/api.yaml`

## Scoring Methodology

Visibility scores are calculated using position, sentiment, and model weight factors. The formula is fully disclosed in `docs/scoring-methodology.md`.

Key differentiator: every score includes a confidence interval showing the precision of the measurement.

## Testing

```bash
# Unit tests (Vitest)
cd apps/web && npm test

# E2E tests (Playwright)
cd apps/web && npx playwright test

# Build health check
cd apps/web && npm run doctor:local
```

## Deployment

1. Set all required environment variables
2. Set `MOCK_AI=false` for production
3. Run database migrations: `npx prisma migrate deploy`
4. Build: `npm run build`
5. Start: `npm start`

The `robots.txt` in `apps/web/public/` blocks AI training crawlers (GPTBot, Google-Extended, OAI-Searchbot, ClaudeBot, PerplexityBot, CCBot) while allowing standard search engines.

## Architecture Decisions

- **Promise.allSettled** for parallel AI calls (never rejects, collects all results)
- **AbortController** with 8s server-side timeout matching frontend
- **429 detection** aborts remaining model calls immediately
- **Mock AI system** with 6 scenario presets for development
- **CSS custom properties** for all colors, spacing, typography (zero raw hex)
- **next/dynamic** for below-fold code splitting
- **Satoshi** local font with preload, Google Fonts with display=swap

## License

Proprietary. All rights reserved.
