# babushka.dev

A minimal Hello World project built with [Hono](https://hono.dev/) for [Cloudflare Workers](https://workers.cloudflare.com/).

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/good-lly/babushka.dev)

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [npm](https://www.npmjs.com/)
- A [Cloudflare account](https://dash.cloudflare.com/sign-up)

### Install dependencies

```bash
npm install
```

### Run locally

```bash
npm run dev
```

### Deploy to Cloudflare Workers

```bash
npm run deploy
```

## Project Structure

```
├── src/
│   └── index.ts      # Main application entry point
├── package.json
├── tsconfig.json
└── wrangler.toml     # Cloudflare Workers configuration
```
