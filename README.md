# SecureAuth API

REST API for authentication and user management, designed to be consumed by other applications (web, mobile, backend-to-backend), built with Java 21, Spring Boot, and JWT.

## Product Viability Assessment (June 2026)

## Dual Assessment Summary

| Perspective | Current Status | Overall Level |
| :--- | :--- | :--- |
| Portfolio Project (showcase) | Strong and interview-ready | High |
| API Product for external consumption | Viable with hardening tasks pending | Medium |

### Portfolio Verdict

**Good portfolio-grade project** for backend/security-focused profiles.

Why it works well as portfolio evidence:

- Real architecture with layered separation and domain-driven endpoint design.
- Security-first implementation (JWT lifecycle, refresh flow, role-based controls).
- Automated testing coverage with current suite passing.
- Practical infrastructure setup (PostgreSQL + Redis + Docker Compose).
- Public-consumption concerns explicitly documented (versioning, CORS, rate-limit).

Portfolio gaps to improve before using it as a flagship project:

- Add CI badges and pipeline evidence in README.
- Add architecture diagram and short ADR-style decisions.
- Include a small Postman collection or quickstart script for demo speed.
- Add a release/changelog section to show maintainability maturity.

### Verdict

**Viable with conditions** as a product consumable by other apps in internal environments or low-to-medium criticality contexts.

**Not ready yet** for public, large-scale product distribution (open SaaS/API) until the quality and hardening risks listed below are addressed.

### Reviewed Evidence

- Clear layered architecture (controller/service/repository/dto/security).
- Solid security baseline for stateless JWT and refresh token management.
- Consistent global error handling for API integrators.
- OpenAPI/Swagger available.
- Local infrastructure with PostgreSQL + Redis + pgAdmin via docker-compose.
- Current test result: `113` tests executed, `0` failures, `0` errors.
- Registration weak-password validation issue fixed and covered by tests.

### Strengths For External Consumption

- Clear HTTP contract by domain (`/api/auth`, `/api/user`, `/api/obviousPasswords`).
- Structured error responses (`timestamp`, `status`, `error`, `message`, `errors`).
- Security with Spring Security + JWT + refresh token rotation/revocation.
- Modern technical foundation (Java 21, Spring Boot 4, Maven).

### Risks And Gaps To Close

- Password policy is now consistently enforced in registration (`8-128` with complexity rules).
- CORS is not defined in `SecurityConfig`, which may block browser cross-origin consumption.
- Explicit API versioning is missing (`/api/v1/...`) to evolve without breaking clients.
- No visible rate limiting / anti-abuse policy for authentication endpoints.
- Previous README was misaligned and truncated; fixed in this version.
- Strong dependency on sensitive environment variables (JWT and DB) without a complete operational guide for rotation/security.

### Product Conclusions

- **As a reusable backend authentication module for internal projects:** strong foundation.
- **As a platform API for third parties:** needs a productization round before being announced as stable.
- **Current external adoption risk:** medium.

### Launch Readiness For API REST Consumption

Current recommendation for external launch:

- **Ready for controlled beta/private integration**.
- **Not yet recommended for broad public launch** until edge-hardening items are complete.

Minimum launch gate for public consumption:

1. CORS allowlist per environment.
2. API versioning contract (`/api/v1`) and compatibility policy.
3. Rate limiting and abuse protections on auth endpoints.
4. Monitoring/alerting and explicit error-handling playbook.
5. Security scanning in CI and dependency/vulnerability checks.

### Executive Recommendation

Move to a short hardening phase (1-2 weeks) before formally exposing it to external consumers.

Priorities:

1. Define CORS per environment (dev/stage/prod).
2. Introduce API versioning (`/api/v1`).
3. Add rate limiting for login/register/refresh.
4. Publish an error policy, token expiration policy, and technical SLA.
5. Add CI quality gates for security scans and contract checks.

## Current Technical State

- Java 21
- Spring Boot 4.0.6
- Spring Security
- JJWT
- Spring Data JPA / Hibernate
- PostgreSQL
- Redis
- SpringDoc OpenAPI
- Maven Wrapper

## Available Endpoints

### Auth (`/api/auth`)

- `POST /login`
- `POST /admin-init`
- `POST /register`
- `POST /logout`
- `POST /refresh`
- `POST /newPassword`

### User (`/api/user`)

- `GET /all`
- `GET /{userId}`
- `PUT /update/{userId}`
- `PUT /role/{userId}`
- `PUT /delete/{userId}`
- `PUT /active/{userId}`
- `DELETE /permanentlyDelete/{userId}`

### Obvious Passwords (`/api/obviousPasswords`)

- `GET /all`
- `GET /{id}`
- `POST /create`
- `POST /bulk`
- `DELETE /delete/{id}`

## Local Run

### 1) Environment Variables

The project requires environment variables for DB and JWT. You can start from `schema.env` and create a `.env` file at the repository root.

Minimum variables:

- `POSTGRES_NAME_DATABASE`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `PGADMIN_DEFAULT_PASSWORD`
- `PGADMIN_DEFAULT_EMAIL`
- `PGADMIN_PORT`
- `JWT_SECRET_KEY`
- `JWT_EXPIRATION`

### 2) Infrastructure

From the repository root:

```bash
docker compose up -d
```

### 3) API

From the `secureauth` folder:

```bash
./mvnw spring-boot:run
```

On Windows PowerShell:

```powershell
.\mvnw.cmd spring-boot:run
```

### 4) API Documentation

- Swagger UI: `http://localhost:8080/swagger-ui/index.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

## Tests

From `secureauth`:

```bash
./mvnw test
```

Current status observed in this assessment:

- Total tests: `113`
- Failures: `0`
- Weak-password validation in registration fixed (password policy kept at min `8`)

## Minimum Roadmap To Release It As A Consumable Product

1. Stabilize the test suite at 100% in CI.
2. Harden edge security (rate limiting, allowlist-based CORS, security headers).
3. Version the contract and freeze a first release (`v1`).
4. Document an integration guide for clients (flows, errors, refresh, expirations).
5. Publish a changelog and compatibility policy.
