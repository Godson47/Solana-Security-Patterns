# Solana Security Patterns

An interactive React/Vite learning site that explains common Solana program security mistakes with vulnerable and safer code examples. The repository also includes Rust example snippets for study.

> **Safety notice:** intentionally vulnerable examples are for education only. Never copy them into production programs or deploy them to a live network. The “secure” examples are illustrative and still require independent review, tests, and validation against the current Solana/Anchor APIs before real use.

## What is included

- React + TypeScript single-page application
- Searchable/interactive pattern pages and code examples
- Educational coverage of signer checks, account ownership and matching, arithmetic safety, PDA seeds, and cross-program invocation
- Standalone Rust snippets for comparison

This repository is currently a **front-end learning application**, not a complete Anchor workspace. There is no root `Anchor.toml`, Cargo workspace, or integrated validator test suite in the current tree, so `anchor build` and `anchor test` are not supported from this repository as-is.

## Requirements

- Node.js 20 or newer
- npm

## Local development

```bash
git clone https://github.com/Godson47/Solana-Security-Patterns.git
cd Solana-Security-Patterns
npm install
npm run dev
```

Vite prints the local URL after the development server starts.

## Build and type-check

```bash
npm run type-check
npm run build
npm run preview
```

The production bundle is written to `dist/`. Review the build output and test all routes in a browser before publishing. The browser router uses paths such as `/pattern/:id`; configure the hosting platform to serve `index.html` as a fallback for client-side routes.

## Deployment

The app can be hosted as a static site on services such as Vercel, Netlify, or Cloudflare Pages:

- Build command: `npm run build`
- Output directory: `dist`
- No server-side secrets or environment variables are required by the current frontend

Use HTTPS in production. Do not add API keys or private credentials to `VITE_*` variables; Vite exposes those values to browser code.

## Security and maintenance

- Treat every code sample as educational material, not a security audit or production-ready smart contract.
- Validate account ownership, signer privileges, PDA derivation, account relationships, arithmetic, and CPI program IDs in real programs.
- Pin and review dependency updates, and run the build and type-check after changes.
- Keep generated output, dependency directories, local environment files, and archives out of source control.

## Contributing

Please include the affected pattern, its threat model, a minimal reproduction, and tests or validation steps when proposing changes. Clearly distinguish exploit demonstrations from mitigations.
