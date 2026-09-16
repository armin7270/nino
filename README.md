# Nino Dashboard

A lightweight and modern web dashboard built with React 19, TypeScript, and Node.js for managing server configurations, connection profiles, traffic quotas, and process supervision.

## Features

- **Web Dashboard**: Clean dark-mode UI with live system telemetry (CPU, RAM, uptime).
- **Profile Management**: Create, edit, and configure secure communication endpoints.
- **Traffic & Validity Tracking**: Monitor bandwidth usage and automatic expiration dates.
- **Diagnostics**: Embedded live process inspection and port monitoring.
- **Container Ready**: Optimized multi-stage Docker build ready for standard container environments.

## Quick Start

### Local Development

```bash
npm install
npm run dev
```

### Production Build

```bash
npm run build
npm start
```

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Web dashboard port |
| `DATA_DIR` | `./data` | Persistent data directory |
| `ADMIN_USERNAME` | `admin` | Initial admin username |
| `ADMIN_PASSWORD` | `admin123` | Initial admin password |
| `GATEWAY_PORT` | `8443` | Primary application service port |

