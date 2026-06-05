# SecureAuth API Starter

Reusable authentication API built with Java 21, Spring Boot, JWT, PostgreSQL, and Redis.

## Quick Start

1. Copy environment file from repository root:

```bash
cp .env.example .env
```

On PowerShell:

```powershell
Copy-Item .env.example .env
```

2. Build and run everything (API + PostgreSQL + Redis + pgAdmin):

```bash
docker compose up --build
```

3. Open API docs:

- Swagger UI: `http://localhost:8080/swagger-ui/index.html`
- OpenAPI: `http://localhost:8080/v3/api-docs`

## Services

- `app`: SecureAuth API (port `8080`)
- `db`: PostgreSQL (mapped with `POSTGRES_PORT`)
- `redis`: Redis (port `6379`)
- `db-admin`: pgAdmin (mapped with `PGADMIN_PORT`)

## Required Environment Variables

- `POSTGRES_NAME_DATABASE`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `PGADMIN_DEFAULT_PASSWORD`
- `PGADMIN_DEFAULT_EMAIL`
- `PGADMIN_PORT`
- `REDIS_HOST`
- `REDIS_PORT`
- `JWT_SECRET_KEY`
- `JWT_EXPIRATION`
- `SPRING_PROFILES_ACTIVE`

## Use As A Starter In New Projects

1. Run this stack and keep `app` exposed on `8080`.
2. In your client project, call auth endpoints from this API.
3. Send JWT access token as `Authorization: Bearer <token>`.
4. Use refresh endpoint to rotate tokens when expired.

## Local Tests (without Docker)

From `secureauth`:

```bash
./mvnw test
```

On PowerShell:

```powershell
.\mvnw.cmd test
```
