# WebApiTemplateGenerator

This is a console-based .NET 8 generator that creates a complete Web API solution following DDD principles, with one project per layer:

- Presentation (WebAPI)
- Logic (with Interfaces and Implementations)
- Repository (with Interfaces and Implementations)
- Cross (for shared models and utilities)

### How It Works

1. **Asks** you for a folder path.
2. **Creates** a .NET 8 solution with the above projects.
3. **Installs** pinned NuGet packages for JWT, EF, bcrypt, and so on.
4. **Generates** code that uses InMemory EF for quick startup and seeds a random admin password.
5. **Writes** an appsettings.json with random secrets (admin password, JWT key, issuer).

### Quick Start

- **Run** the generator.
- **Open** the generated `MyAppSolution.sln`.
- **Build** and run `MyApp.Presentation`.

Enjoy your new solution!
