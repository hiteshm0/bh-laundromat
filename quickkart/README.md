# QuickKart

A local store with six products, five sample customers and seeded orders. All account, identity and payment data is fake. No payment or identity service is contacted.

## Requirements

Node.js 22 or newer, npm, and Bun for the frontend. SQLite is included by better-sqlite3. If a native prebuilt binary is unavailable, install your operating system’s C++ build tools and Python.

## Start locally

From the project root:

```sh
npm install --prefix server
node server/index.js
```

The API listens only at `http://127.0.0.1:3001`. In another terminal:

```sh
bun install
bun run dev --host 127.0.0.1 --port 8080
```

Open `http://localhost:8080`. Start the API before opening or refreshing the storefront. Local requests use the SQLite-backed API when it is available. The hosted Lovable preview uses in-memory sample data instead and does not run the standalone server. Do not deploy the standalone server or change its loopback binding.

Product photographs are served by the project asset host. No external API services are called by either store mode. Fake browser credentials are fixtures only and never used to contact services.

## Accounts

| Name | Phone | Role |
| --- | --- | --- |
| Aarav Sharma | 9000000001 | Student |
| Diya Patel | 9000000002 | Student |
| Kabir Rao | 9000000003 | Student |
| Meera Iyer | 9000000004 | Student |
| Rohan Das | 9000000005 | Admin |

Request a phone code on `/login` and enter the displayed code. Local API codes are generated per request; preview codes are `123456`. Local sessions last one hour and survive page refresh within the same browser tab. Basket contents and preview sessions stay in memory. Checkout creates a simulated payment order; no money moves.

Pages: `/`, `/login`, `/orders`, `/profile`, `/admin`, `/checkout`.

## Local API

| Method | Path |
| --- | --- |
| GET | /api/health |
| GET | /api/search?q=notebook |
| POST | /api/auth/send-otp |
| POST | /api/auth/verify-otp |
| GET | /api/me |
| GET | /api/orders |
| GET | /api/orders/:id |
| GET | /api/admin/users |
| GET | /api/admin/orders |
| POST | /api/profile |
| POST | /api/checkout |

Authenticated requests use `Authorization: Bearer <token>` from code verification. `/api/admin/orders` requires an admin account.

Comparison endpoints live under `/api/safe`: `/search`, `/admin/users`, `/orders/:id`, `/auth/send-otp`, `/checkout`, `/payments/confirm`. The comparison code-generation endpoint has no delivery integration: it generates and retains a code locally but does not send it. Use the normal local sign-in endpoint to get a token for authenticated comparison requests.

The simulated comparison payment flow:

1. Create an order with `POST /api/safe/checkout` and `{ "items": [{ "productId": 1, "quantity": 1 }] }`.
2. Call `POST /api/safe/payments/confirm` with `{ "orderId": 1006 }`, substituting the returned order ID.
3. Call `/api/safe/checkout` with `orderId`, the returned `paymentId`, and `signature`.

Receipts exist only in server memory and are verified against that server-held record. There is no external processor.

## Tests and reset

```sh
node --test server/test/store.test.js
bunx vitest run src/test/app-routing.test.tsx
```

Server tests use an in-memory database. To reset local data, stop the server, delete `server/quickkart.sqlite` and any matching `-shm` and `-wal` files, then start it again.

The scoring inventory is in `GROUND_TRUTH.md`. Remove that guide before scanning and exclude test files, generated output and dependency directories from first-party source results. Install server dependencies before evaluating package reachability.
