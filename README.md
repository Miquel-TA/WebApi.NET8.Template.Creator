# MyAppSolution

A .NET 8 Web API template using DDD with four projects:
- **Cross**: Shared `User` model, `JwtUtils` & `BcryptUtils`.
- **Logic**: Business logic with Interfaces & Implementations, DI-ready.
- **Repository**: EF Core InMemory DB, seeded with random admin credentials.
- **Presentation**: ASP.NET Core WebAPI (Swagger, JWT auth, Serilog logs).

## Features
- **JWT** usage: Acquire a token via `/api/crud/login` (passing username & password). Then use the `Authorization: Bearer <token>` header on protected endpoints.
- **DI**: The solution wires up the logic & repository automatically (ServiceRegistration).
- **References**: Projects reference Cross for shared code, Logic references Repository for DB, etc.
- **Pinned Packages**: EF 8.0.11, JWT 8.3.0, bcrypt 4.0.3, Serilog 8.0.3, Swashbuckle 7.2.0 / 8.0.2.
- **InMemory DB**: A `User` entity is CRUD-capable, default “admin” is seeded with random password from `appsettings.json`.

## Usage
- **Build** & **Run** the `MyApp.Presentation` project.
- **Swagger** available at `/swagger`.
- **Login** with `POST /api/crud/login?username=admin&password=...`.
- **CRUD** endpoints for user exist in `POST/GET/PUT/DELETE /api/crud/users`.
- **Log** in console & `Logs/myapp-.log`.
