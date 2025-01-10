# WebApiTemplateGenerator

Take a look at the generated solution - https://github.com/Miquel-TA/WebApi.NET8.Template

Creates a full .NET 8 Web API solution with a DDD architecture:
- **Cross** (Models & Utils)
- **Logic** (Interfaces & Implementations)
- **Repository** (Interfaces & Implementations)
- **Presentation** (WebAPI)

## Features
- **JWT** authentication (via Microsoft.AspNetCore.Authentication.JwtBearer).
- **Dependency Injection** for repository & logic layers.
- **Automatic references** (each project references Cross, etc.).
- **Pinned packages**: EF Core (8.0.11), JWT (8.3.0), bcrypt (4.0.3), Serilog (8.0.3), Swashbuckle (7.2.0 / 8.0.2).
- **InMemory** EF database seeded with a random admin password.
- **CRUD** endpoints for `User` entity in the Repository & Logic.
- **Random** secrets and admin password stored in `appsettings.json`.

## Usage
1. **Run** this generator console app.
2. **Enter** a path when prompted.
3. **Open** the newly created `MyAppSolution.sln`.
4. **Build** & **run** `MyApp.Presentation`.
