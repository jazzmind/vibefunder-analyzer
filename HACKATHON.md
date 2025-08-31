## Hackathon Pitch: VibeFunder × Analyzer

### What we built (prototype)

- **Creator-to-Backer bridge**: A campaign platform (VibeFunder) that turns a repository/website into a compelling fundraising campaign with milestones, pledge tiers, and Stripe checkout.
- **Production-readiness analyzer (this repo)**: An HTTP API that clones a target repo and runs scanners (Semgrep, Gitleaks, SBOM/Grype), then synthesizes a concise, actionable gap analysis. It also supports feature scanning and aggregation of repo docs/website content.
- **Tight integration**: The VibeFunder app calls this Analyzer API with OAuth2 client credentials, polls job status, pulls SARIF reports, and uses an AI service to generate a milestone-oriented gap analysis and a pragmatic master plan for delivery.

This is a pragmatic prototype designed for a demo; some parts are minimal and will need hardening before broader use.

### Why it matters

- **Faster scoping**: Turn raw code and websites into a clear plan with milestones and acceptance criteria inspired by OWASP ASVS L1–L2.
- **Backer trust**: Milestones and clear acceptance criteria help justify escrow and staged release of funds.
- **Delivery alignment**: Creators, backers, and implementors share the same roadmap, grounded in the actual codebase.

### How it works (high level)

```mermaid
graph LR
  A[Creator edits campaign in VibeFunder] --> B[Next.js API routes]
  B -->|OAuth2 client_credentials| C[Analyzer API]
  C --> D[Clone repo + run scanners]
  D --> E[Store SARIF + reports]
  E --> F[Analyzer jobs endpoints]
  B -->|poll job + fetch reports| F
  B --> G[AI Gap Synthesis (VibeFunder)]
  G --> H[Milestones + Acceptance + Scope]
  H --> A

  subgraph Optional
    B --> I[Aggregate: repo .md + website text]
    I --> J[AI Master Plan (VibeFunder)]
    J --> H
  end
```

### Demo script (5–7 minutes)

1) Analyzer API (this repo)
- Start the API locally:
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r tools/indexer/requirements.txt -r agents/requirements.txt
make api-run  # uvicorn on :8080
```
- Provision credentials for the VibeFunder app to call the Analyzer:
```bash
make gen-client  # prints OAUTH_* for analyzer and ANALYZER_* for app
```

2) VibeFunder app
- Configure environment variables in the app (e.g., `.env.local`):
  - `ANALYZER_BASE_URL`: analyzer API base URL (e.g., `http://localhost:8080`)
  - `ANALYZER_CLIENT_ID` and `ANALYZER_CLIENT_SECRET`: from `make gen-client`
  - Optional: `PERPLEXITY_API_KEY` for competitor research
  - Optional: `ANALYZER_GITHUB_TOKEN` or connect the GitHub App in the UI
- Run the app dev server and sign in as a demo user.
- Open an existing campaign (or create one), then go to Edit.

3) Show the integration in the Edit page
- In the Campaign tab, set a repo URL and optionally a website URL.
- In the Analysis tab:
  - Click **Generate from Campaign & Docs** to produce a master plan using repo docs/website.
  - Click **Run and Generate** to start Analyzer scanners, poll job status, and synthesize a gap analysis into milestones with acceptance/scope.
- Optionally click **Scan Features** to check for the presence of planned features in the repo.
- Add/adjust milestones and save.

4) Show the campaign page
- Demonstrate pledge tiers and Stripe checkout flow.

### What’s implemented

- Analyzer API (this repo)
  - OAuth2 client credentials (`POST /oauth/token`)
  - Job lifecycle (`POST /api/v1/analyze`, `GET /api/v1/jobs/:id`, `GET /api/v1/jobs/:id/reports/*`, `GET /api/v1/jobs/:id/sow`)
  - Feature scan and aggregation endpoints (`/api/v1/features`, `/api/v1/aggregate`)
- VibeFunder app integration (separate repo)
  - `lib/analyzerClient.ts`: obtains tokens, starts jobs, polls, and fetches reports.
  - `app/api/analyzer/*`: lightweight proxy/coordination routes for start, jobs, gap synthesis, master plan, features, aggregate.
  - `lib/services/AnalyzerGapService.ts`: turns SARIF into milestones with acceptance/scope via an AI schema.
  - `lib/services/MasterPlanService.ts`: synthesizes a product master plan from campaign fields + repo docs + optional website text.
  - `app/campaigns/[id]/edit/CampaignEditForm.tsx`: UI to trigger plan/gap/feature scans and display results; also handles GitHub App connection status.
  - `app/campaigns/[id]/client.tsx`: pledge tiers and Stripe checkout button UX.

### Limitations and next steps

- Scanners depend on local CLIs for full fidelity; missing tools reduce findings.
- Gap and plan quality depend on inputs (repo docs/website). Outputs should be reviewed and refined.
- Feature scan is heuristic; consider richer semantic indexing and code parsing.
- Tighten error handling, retries, and user feedback states; add background job webhooks.
- Add authZ and rate limiting for hosted Analyzer; expand CI/CD integration and SBOM policy gates.

### Talking points for the pitch (60–90 seconds)

- Problem: Creators need credible plans and trust; implementors need scoping; backers need confidence.
- Our prototype reads the repo and website, runs scanners, and instantly proposes a realistic plan with milestones and acceptance criteria.
- Those milestones drive the funding narrative and staged escrow releases. Everyone aligns on the same roadmap.
- Today it works end-to-end for a demo; we’ll harden scanners, indexing, and acceptance checks next.

### Appendix: Key references

- Analyzer API (this repo): see `README.md` for the endpoint reference and local/dev instructions.
- VibeFunder app integration (selected files):
  - `lib/analyzerClient.ts`
  - `app/api/analyzer/start/route.ts`, `.../jobs/[jobId]/route.ts`, `.../gap/route.ts`, `.../master-plan/route.ts`, `.../features/route.ts`, `.../aggregate/route.ts`
  - `lib/services/AnalyzerGapService.ts`, `lib/services/MasterPlanService.ts`
  - `app/campaigns/[id]/edit/CampaignEditForm.tsx`, `app/campaigns/[id]/client.tsx`


