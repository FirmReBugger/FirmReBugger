# FirmReBugger Frontend

This repository is the **React+TypeScript** frontend for the FirmReBugger web application. It is built with [Vite](https://vitejs.dev/) and serves solely as a UI layer—the business logic for running, queueing, triaging and viewing jobs is implemented entirely on the server (see `src/firmrebugger` in the main repo).

## What it does

The web frontend provides users with:

- A **job manager dashboard** showing running and queued tasks
- Controls to start/stop the manager and individual jobs
- Real‑time updates using server‑sent events
- Views for task details and triage results
- A **report dashboard** where users can inspect outcomes produced by the job manager

## QuickStart 
To launch the FirmReBugger web application, run:

```
uv run frb app 
```

The app will be available at `http://localhost:5000` by default and will proxy API requests to the backend.

## Development

To start the dev server with hot reload:

```bash
cd src/firmrebugger-web
npm install
npm run dev
```


## Building

```bash
npm run build
```

The production files are output to `dist/` and can be served by any static web server or included in the Python Docker image.

