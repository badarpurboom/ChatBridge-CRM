# My Business CRM - WhatsApp Connected

## Setup (Step by Step)

1. Install Node.js (LTS)
2. Open this folder in terminal
3. Update `.env`
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
   - `SESSION_SECRET`
4. Install dependencies
   ```bash
   npm install
   ```
5. Start server
   ```bash
   node server.js
   ```
6. Open in browser
   - Agent UI: `http://localhost:3000`
   - Admin UI: `http://localhost:3000/admin`

## Login
Use `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`.

## WhatsApp Connect
WhatsApp connect only Admin panel se hota hai.

## Data Storage
- `crm.db` (SQLite database)
- `whatsapp-session/` (WhatsApp login session)

## Notes
- Server band karoge to WhatsApp disconnect ho jayega.
- First time QR scan required; session save rehta hai.
