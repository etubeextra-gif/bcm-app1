# BCM Backend — Secret Messages

Pure Node.js backend with **zero external dependencies**.

## Quick Start

```bash
node server.js
```

Server starts on **http://localhost:3000**

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | No | Register, returns `{ token, login_id }` |
| POST | `/auth/login` | No | Login, returns `{ token, login_id }` |
| GET | `/profile` | Yes | Get user stats |
| GET | `/messages` | Yes | List your messages |
| POST | `/messages/text` | Yes | Create text message |
| POST | `/messages/media` | Yes | Upload image/video message |
| POST | `/redeem` | No | Redeem a BCM code |

## Data Storage

- **Database**: `data/db.json` (JSON file)
- **Uploads**: `data/uploads/` (binary files)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `JWT_SECRET` | (random) | JWT signing secret — set this in production! |

## Frontend

Open `index.html` in a browser (or serve it from the backend).  
The frontend connects to `http://localhost:3000` by default.

## Production Notes

1. Set a stable `JWT_SECRET` environment variable
2. Run behind a reverse proxy (nginx/caddy) with HTTPS
3. For scale, swap `data/db.json` for a real database (SQLite, PostgreSQL)
