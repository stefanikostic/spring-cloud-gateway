# Spring Cloud Gateway (Elevate Resume)

A Spring Cloud Gateway MVC service that fronts the Elevate Resume backend services with JWT-based authentication.

## Stack
- Java 23
- Spring Boot 3.3.8
- Spring Cloud 2023.0.5

## Configuration
The main configuration lives in `src/main/resources/application.yml`.

### Environment variables
- `JWT_SECRET_KEY`: secret used to verify JWT signatures.

### Server
- Port: `8080`

### CORS
- Allowed origin: `http://localhost:5173/`
- Allowed methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`

## Routes
The gateway forwards requests to local upstream services:

| Path pattern | Upstream | Notes |
| --- | --- | --- |
| `/auth/**` | `http://localhost:8081/` | Auth endpoints are public (no JWT required) |
| `external/resume/**` | `http://localhost:8082/` | JWT required |
| `internal/resume/**` | `http://localhost:8082/` | JWT required |
| `resume/**` | `http://localhost:8082/` | JWT required |
| `/preview-resume/**` | `http://localhost:8083/` | JWT required |

## Authentication
- The gateway reads a JWT from the `AUTH_TOKEN` cookie.
- Valid tokens are parsed and the authenticated user is set in the security context.
- Requests to `/auth/**` are permitted without authentication; all others require a valid JWT.

## Run locally
Ensure the upstream services on ports `8081`, `8082`, and `8083` are running.

```powershell
$env:JWT_SECRET_KEY = "<your-secret>"
./mvnw spring-boot:run
```

## Tests
```powershell
./mvnw test
```

## Notes
- JWT expiration is configured via `security.jwt.expiration-time` in `application.yml`.

