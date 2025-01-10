using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace WebApiTemplateGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter the full path where you want to create the solution:");
            var basePath = Console.ReadLine()?.Trim();

            if (string.IsNullOrWhiteSpace(basePath))
            {
                Console.WriteLine("Invalid path. Exiting...");
                return;
            }

            // Ensure directory
            if (!Directory.Exists(basePath))
            {
                Console.WriteLine($"Directory '{basePath}' does not exist. Creating it...");
                Directory.CreateDirectory(basePath);
            }

            // 1) Folder structure (one project per layer, subfolders for interfaces/implementations in Logic/Repository)
            CreateFolderStructure(basePath);

            // 2) Create the solution
            RunCommand("dotnet", "new sln -n MyAppSolution", basePath);

            // 3) Create projects (with --output . to avoid nested subfolders)
            CreateProjects(basePath);

            // 4) Add them to solution
            AddProjectsToSolution(basePath);

            // 5) Add references + pinned NuGet packages
            AddReferencesAndPackages(basePath);

            // 6) Remove Class1.cs from each new Class Library
            RemoveDefaultClass1Files(basePath);

            // 7) Add code files
            AddCodeFiles(basePath);

            // 8) Generate random admin password and JWT secrets in appsettings.json (in Presentation)
            CreateAppSettingsWithRandomSecrets(basePath);

            Console.WriteLine("DDD structure with one project per layer + in-memory DB + random credentials created successfully!");
        }

        private static void CreateFolderStructure(string basePath)
        {
            Directory.CreateDirectory(Path.Combine(basePath, "Presentation"));

            Directory.CreateDirectory(Path.Combine(basePath, "Logic"));
            Directory.CreateDirectory(Path.Combine(basePath, "Logic", "Interfaces"));
            Directory.CreateDirectory(Path.Combine(basePath, "Logic", "Implementations"));
            Directory.CreateDirectory(Path.Combine(basePath, "Logic", "Implementations", "Dependencies"));

            Directory.CreateDirectory(Path.Combine(basePath, "Repository"));
            Directory.CreateDirectory(Path.Combine(basePath, "Repository", "Interfaces"));
            Directory.CreateDirectory(Path.Combine(basePath, "Repository", "Implementations"));

            Directory.CreateDirectory(Path.Combine(basePath, "Cross"));
            Directory.CreateDirectory(Path.Combine(basePath, "Cross", "Models"));
            Directory.CreateDirectory(Path.Combine(basePath, "Cross", "Utils"));
        }

        private static void CreateProjects(string basePath)
        {
            // 1) Presentation in "Presentation" folder
            RunCommand("dotnet",
                "new webapi --framework net8.0 -n MyApp.Presentation --output .",
                Path.Combine(basePath, "Presentation"));

            // 2) Logic in "Logic" folder
            RunCommand("dotnet",
                "new classlib --framework net8.0 -n MyApp.Logic --output .",
                Path.Combine(basePath, "Logic"));

            // 3) Repository in "Repository" folder
            RunCommand("dotnet",
                "new classlib --framework net8.0 -n MyApp.Repository --output .",
                Path.Combine(basePath, "Repository"));

            // 4) Cross in "Cross" folder
            RunCommand("dotnet",
                "new classlib --framework net8.0 -n MyApp.Cross --output .",
                Path.Combine(basePath, "Cross"));
        }

        private static void AddProjectsToSolution(string basePath)
        {
            var slnPath = Path.Combine(basePath, "MyAppSolution.sln");

            RunCommand("dotnet",
                $"sln \"{slnPath}\" add \"{Path.Combine(basePath, "Presentation", "MyApp.Presentation.csproj")}\"",
                basePath);

            RunCommand("dotnet",
                $"sln \"{slnPath}\" add \"{Path.Combine(basePath, "Logic", "MyApp.Logic.csproj")}\"",
                basePath);

            RunCommand("dotnet",
                $"sln \"{slnPath}\" add \"{Path.Combine(basePath, "Repository", "MyApp.Repository.csproj")}\"",
                basePath);

            RunCommand("dotnet",
                $"sln \"{slnPath}\" add \"{Path.Combine(basePath, "Cross", "MyApp.Cross.csproj")}\"",
                basePath);
        }

        private static void AddReferencesAndPackages(string basePath)
        {
            var presCsproj = Path.Combine(basePath, "Presentation", "MyApp.Presentation.csproj");
            var logicCsproj = Path.Combine(basePath, "Logic", "MyApp.Logic.csproj");
            var repoCsproj = Path.Combine(basePath, "Repository", "MyApp.Repository.csproj");
            var crossCsproj = Path.Combine(basePath, "Cross", "MyApp.Cross.csproj");

            // All reference Cross
            RunCommand("dotnet", $"add \"{presCsproj}\" reference \"{crossCsproj}\"", basePath);
            RunCommand("dotnet", $"add \"{logicCsproj}\" reference \"{crossCsproj}\"", basePath);
            RunCommand("dotnet", $"add \"{repoCsproj}\" reference \"{crossCsproj}\"", basePath);

            // Presentation references Logic
            RunCommand("dotnet", $"add \"{presCsproj}\" reference \"{logicCsproj}\"", basePath);

            // Logic references Repository
            RunCommand("dotnet", $"add \"{logicCsproj}\" reference \"{repoCsproj}\"", basePath);

            // CROSS => JWT, bcrypt, config
            RunCommand("dotnet",
                $"add \"{crossCsproj}\" package System.IdentityModel.Tokens.Jwt --version 8.3.0 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{crossCsproj}\" package Microsoft.IdentityModel.Tokens --version 8.3.0 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{crossCsproj}\" package Microsoft.Extensions.Configuration.Abstractions --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{crossCsproj}\" package BCrypt.Net-Next --version 4.0.3 --source https://api.nuget.org/v3/index.json",
                basePath);

            // REPOSITORY => EF
            RunCommand("dotnet",
                $"add \"{repoCsproj}\" package Microsoft.EntityFrameworkCore --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{repoCsproj}\" package Microsoft.EntityFrameworkCore.SqlServer --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{repoCsproj}\" package Microsoft.EntityFrameworkCore.Sqlite --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);

            // LOGIC => EF for AddDbContext, etc.
            RunCommand("dotnet",
                $"add \"{logicCsproj}\" package Microsoft.EntityFrameworkCore --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{logicCsproj}\" package Microsoft.Extensions.DependencyInjection --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{logicCsproj}\" package Microsoft.Extensions.Configuration.Abstractions --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            // InMemory provider:
            RunCommand("dotnet",
                $"add \"{logicCsproj}\" package Microsoft.EntityFrameworkCore.InMemory --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);

            // PRESENTATION => JWT Bearer, Serilog, Swashbuckle
            RunCommand("dotnet",
                $"add \"{presCsproj}\" package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.11 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{presCsproj}\" package Serilog.AspNetCore --version 8.0.3 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{presCsproj}\" package Swashbuckle.AspNetCore --version 7.2.0 --source https://api.nuget.org/v3/index.json",
                basePath);
            RunCommand("dotnet",
                $"add \"{presCsproj}\" package Swashbuckle.AspNetCore.Filters --version 8.0.2 --source https://api.nuget.org/v3/index.json",
                basePath);
        }

        private static void RemoveDefaultClass1Files(string basePath)
        {
            var crossFile = Path.Combine(basePath, "Cross", "Class1.cs");
            if (File.Exists(crossFile)) File.Delete(crossFile);

            var logicFile = Path.Combine(basePath, "Logic", "Class1.cs");
            if (File.Exists(logicFile)) File.Delete(logicFile);

            var repoFile = Path.Combine(basePath, "Repository", "Class1.cs");
            if (File.Exists(repoFile)) File.Delete(repoFile);
        }

        private static void AddCodeFiles(string basePath)
        {
            AddPresentationFiles(basePath);
            AddCrossFiles(basePath);
            AddLogicFiles(basePath);
            AddRepositoryFiles(basePath);
        }

        // --------------------- PRESENTATION ---------------------
        private static void AddPresentationFiles(string basePath)
        {
            var presProjPath = Path.Combine(basePath, "Presentation");
            var programCsPath = Path.Combine(presProjPath, "Program.cs");

            // 1) Program.cs: reads from appsettings, throws if missing
            var programCsContent = @"using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Swashbuckle.AspNetCore.Filters;
using System.Text;
using MyApp.Logic.Implementations.Dependencies; // for ServiceRegistration
using Microsoft.EntityFrameworkCore;
using MyApp.Repository; 
using MyApp.Cross.Models; 
using MyApp.Cross.Utils;

var builder = WebApplication.CreateBuilder(args);

// Add the JSON settings from appsettings.json
builder.Configuration.AddJsonFile(""appsettings.json"", optional: false, reloadOnChange: false);

// Check that AdminSettings:Password, JwtSettings:Key, and JwtSettings:Issuer exist
var adminPassword = builder.Configuration[""AdminSettings:Password""];
if (string.IsNullOrWhiteSpace(adminPassword))
    throw new Exception(""AdminSettings:Password is missing in appsettings.json"");

var jwtKey = builder.Configuration[""JwtSettings:Key""];
if (string.IsNullOrWhiteSpace(jwtKey))
    throw new Exception(""JwtSettings:Key is missing in appsettings.json"");

var jwtIssuer = builder.Configuration[""JwtSettings:Issuer""];
if (string.IsNullOrWhiteSpace(jwtIssuer))
    throw new Exception(""JwtSettings:Issuer is missing in appsettings.json"");

// Logging with Serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File(""Logs/myapp-.log"", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog(Log.Logger);

// Controllers
builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition(""oauth2"", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = ""Bearer token"",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Name = ""Authorization"",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = ""bearer""
    });
    c.OperationFilter<SecurityRequirementsOperationFilter>();
});

// Setup JWT
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey)),
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization();

// Setup logic with an in-memory database:
ServiceRegistration.ConfigureServices_InMemory(builder.Services, builder.Configuration);

var app = builder.Build();

// Use the config-based admin password
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MyAppDbContext>();
    if (!db.Users.Any(u => u.Username == ""admin""))
    {
        var user = new User
        {
            Username = ""admin"",
            PasswordHash = BcryptUtils.HashPassword(adminPassword)
        };
        db.Users.Add(user);
        db.SaveChanges();

        Console.WriteLine($""Default admin user is 'admin' with password from appsettings: {adminPassword}"");
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
";
            File.WriteAllText(programCsPath, programCsContent);

            // 2) Minimal CrudController
            var controllersDir = Path.Combine(presProjPath, "Controllers");
            Directory.CreateDirectory(controllersDir);

            var crudControllerPath = Path.Combine(controllersDir, "CrudController.cs");
            var crudControllerContent = @"using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MyApp.Logic.Interfaces;

namespace MyApp.Presentation.Controllers
{
    [ApiController]
    [Route(""api/[controller]"")]
    [Authorize]
    public class CrudController : ControllerBase
    {
        private readonly IUserLogic _logic;

        public CrudController(IUserLogic logic)
        {
            _logic = logic;
        }

        [HttpGet(""users"")]
        public IActionResult GetAllUsers()
        {
            var users = _logic.GetAllUsers();
            return Ok(users);
        }

        [HttpPost(""users"")]
        public IActionResult CreateUser([FromQuery] string username, [FromQuery] string password)
        {
            var user = _logic.CreateUser(username, password);
            if (user == null) return BadRequest(""Could not create user."");
            return Ok(user);
        }

        [HttpPut(""users/{id}"")]
        public IActionResult UpdateUser(int id, [FromQuery] string username, [FromQuery] string password)
        {
            var success = _logic.UpdateUser(id, username, password);
            if (!success) return NotFound(""Update failed."");
            return Ok(""User updated"");
        }

        [HttpDelete(""users/{id}"")]
        public IActionResult DeleteUser(int id)
        {
            var success = _logic.DeleteUser(id);
            if (!success) return NotFound(""Delete failed."");
            return Ok(""User deleted"");
        }

        [AllowAnonymous]
        [HttpPost(""login"")]
        public IActionResult Login([FromQuery] string username, [FromQuery] string password)
        {
            var token = _logic.Login(username, password);
            if (token == null) return Unauthorized(""Invalid credentials"");
            return Ok(new { Token = token });
        }
    }
}
";
            File.WriteAllText(crudControllerPath, crudControllerContent);
        }

        // --------------------- CROSS ---------------------
        private static void AddCrossFiles(string basePath)
        {
            var crossProjDir = basePath + "/Cross";

            // Models subfolder
            var modelsDir = Path.Combine(crossProjDir, "Models");
            Directory.CreateDirectory(modelsDir);

            var userFile = Path.Combine(modelsDir, "User.cs");
            var userContent = @"namespace MyApp.Cross.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
    }
}
";
            File.WriteAllText(userFile, userContent);

            // Utils subfolder
            var utilsDir = Path.Combine(crossProjDir, "Utils");
            Directory.CreateDirectory(utilsDir);

            var bcryptFile = Path.Combine(utilsDir, "BcryptUtils.cs");
            var bcryptContent = @"using BCrypt.Net;

namespace MyApp.Cross.Utils
{
    public static class BcryptUtils
    {
        public static string HashPassword(string plainPassword)
        {
            return BCrypt.Net.BCrypt.HashPassword(plainPassword, 10);
        }

        public static bool VerifyPassword(string plainPassword, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
        }
    }
}
";
            File.WriteAllText(bcryptFile, bcryptContent);

            var jwtFile = Path.Combine(utilsDir, "JwtUtils.cs");
            var jwtContent = @"using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace MyApp.Cross.Utils
{
    public static class JwtUtils
    {
        public static string GenerateToken(string username, IConfiguration config)
        {
            var key = config[""JwtSettings:Key""];
            var issuer = config[""JwtSettings:Issuer""];

            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(issuer))
                throw new Exception(""JWT key or issuer not found in configuration."");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: null,
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
";
            File.WriteAllText(jwtFile, jwtContent);
        }

        // --------------------- LOGIC ---------------------
        private static void AddLogicFiles(string basePath)
        {
            var logicProjectDir = basePath + "/Logic";

            // 1) Interfaces subfolder
            var interfacesDir = Path.Combine(logicProjectDir, "Interfaces");
            Directory.CreateDirectory(interfacesDir);

            var iUserLogicPath = Path.Combine(interfacesDir, "IUserLogic.cs");
            var iUserLogicContent = @"using System.Collections.Generic;
using MyApp.Cross.Models;

namespace MyApp.Logic.Interfaces
{
    public interface IUserLogic
    {
        IEnumerable<User> GetAllUsers();
        User? CreateUser(string username, string password);
        bool UpdateUser(int id, string username, string password);
        bool DeleteUser(int id);
        string? Login(string username, string password);
    }
}
";
            File.WriteAllText(iUserLogicPath, iUserLogicContent);

            // 2) Implementations subfolder (plus "Dependencies" subfolder)
            var implDir = Path.Combine(logicProjectDir, "Implementations");
            Directory.CreateDirectory(implDir);

            var userLogicPath = Path.Combine(implDir, "UserLogic.cs");
            var userLogicContent = @"using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using MyApp.Cross.Models;
using MyApp.Cross.Utils;
using MyApp.Logic.Interfaces;
using MyApp.Repository;

namespace MyApp.Logic.Implementations
{
    public class UserLogic : IUserLogic
    {
        private readonly IUserRepository _repo;
        private readonly IConfiguration _config;

        public UserLogic(IUserRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        public IEnumerable<User> GetAllUsers()
        {
            return _repo.GetAllUsers();
        }

        public User? CreateUser(string username, string password)
        {
            var hash = BcryptUtils.HashPassword(password);
            return _repo.CreateUser(username, hash);
        }

        public bool UpdateUser(int id, string username, string password)
        {
            var hash = BcryptUtils.HashPassword(password);
            return _repo.UpdateUser(id, username, hash);
        }

        public bool DeleteUser(int id)
        {
            return _repo.DeleteUser(id);
        }

        public string? Login(string username, string password)
        {
            var user = _repo.GetUserByUsername(username);
            if (user == null) return null;
            bool valid = BcryptUtils.VerifyPassword(password, user.PasswordHash);
            if (!valid) return null;
            return JwtUtils.GenerateToken(user.Username, _config);
        }
    }
}
";
            File.WriteAllText(userLogicPath, userLogicContent);

            var dependenciesDir = Path.Combine(implDir, "Dependencies");
            Directory.CreateDirectory(dependenciesDir);

            var serviceRegPath = Path.Combine(dependenciesDir, "ServiceRegistration.cs");
            var serviceRegContent = @"using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MyApp.Logic.Interfaces;
using MyApp.Repository;

namespace MyApp.Logic.Implementations.Dependencies
{
    public static class ServiceRegistration
    {
        // We'll do an InMemory DB for easy testing.
        public static void ConfigureServices_InMemory(IServiceCollection services, IConfiguration configuration)
        {
            // InMemory DB
            services.AddDbContext<MyAppDbContext>(options =>
                options.UseInMemoryDatabase(""InMemoryDb""));

            // Register repo
            services.AddScoped<IUserRepository, UserRepository>();

            // Register logic
            services.AddScoped<IUserLogic, UserLogic>();
        }
    }
}
";
            File.WriteAllText(serviceRegPath, serviceRegContent);
        }

        // --------------------- REPOSITORY ---------------------
        private static void AddRepositoryFiles(string basePath)
        {
            var repoProjectDir = basePath + "/Repository";

            var interfacesDir = Path.Combine(repoProjectDir, "Interfaces");
            Directory.CreateDirectory(interfacesDir);

            var implementationsDir = Path.Combine(repoProjectDir, "Implementations");
            Directory.CreateDirectory(implementationsDir);

            // IUserRepository
            var iUserRepoPath = Path.Combine(interfacesDir, "IUserRepository.cs");
            var iUserRepoContent = @"using System.Collections.Generic;
using MyApp.Cross.Models;

namespace MyApp.Repository
{
    public interface IUserRepository
    {
        IEnumerable<User> GetAllUsers();
        User? CreateUser(string username, string passwordHash);
        bool UpdateUser(int id, string username, string passwordHash);
        bool DeleteUser(int id);
        User? GetUserByUsername(string username);
    }
}
";
            File.WriteAllText(iUserRepoPath, iUserRepoContent);

            // MyAppDbContext
            var dbContextPath = Path.Combine(implementationsDir, "MyAppDbContext.cs");
            var dbContextContent = @"using Microsoft.EntityFrameworkCore;
using MyApp.Cross.Models;

namespace MyApp.Repository
{
    public class MyAppDbContext : DbContext
    {
        public MyAppDbContext(DbContextOptions<MyAppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; } = null!;
    }
}
";
            File.WriteAllText(dbContextPath, dbContextContent);

            // UserRepository
            var userRepoPath = Path.Combine(implementationsDir, "UserRepository.cs");
            var userRepoContent = @"using System.Collections.Generic;
using System.Linq;
using MyApp.Cross.Models;

namespace MyApp.Repository
{
    public class UserRepository : IUserRepository
    {
        private readonly MyAppDbContext _db;

        public UserRepository(MyAppDbContext db)
        {
            _db = db;
        }

        public IEnumerable<User> GetAllUsers()
        {
            return _db.Users.ToList();
        }

        public User? GetUserByUsername(string username)
        {
            return _db.Users.FirstOrDefault(u => u.Username == username);
        }

        public User? CreateUser(string username, string passwordHash)
        {
            var user = new User
            {
                Username = username,
                PasswordHash = passwordHash
            };
            _db.Users.Add(user);
            int rows = _db.SaveChanges();
            return (rows > 0) ? user : null;
        }

        public bool UpdateUser(int id, string username, string passwordHash)
        {
            var user = _db.Users.FirstOrDefault(u => u.Id == id);
            if (user == null) return false;
            user.Username = username;
            user.PasswordHash = passwordHash;
            int rows = _db.SaveChanges();
            return (rows > 0);
        }

        public bool DeleteUser(int id)
        {
            var user = _db.Users.FirstOrDefault(u => u.Id == id);
            if (user == null) return false;
            _db.Users.Remove(user);
            int rows = _db.SaveChanges();
            return (rows > 0);
        }
    }
}
";
            File.WriteAllText(userRepoPath, userRepoContent);
        }

        /// <summary>
        /// Creates an appsettings.json file in the Presentation folder with random Admin password & random JwtSettings.
        /// Also adds the requested Logging + AllowedHosts settings.
        /// </summary>
        private static void CreateAppSettingsWithRandomSecrets(string basePath)
        {
            var presentationPath = Path.Combine(basePath, "Presentation");
            var appSettingsFile = Path.Combine(presentationPath, "appsettings.json");

            // Generate random admin password
            var passBuffer = new byte[32];
            RandomNumberGenerator.Fill(passBuffer);
            string randomAdminPassword = Convert.ToBase64String(passBuffer);

            // Generate random JWT key
            var keyBuffer = new byte[32];
            RandomNumberGenerator.Fill(keyBuffer);
            string randomKey = Convert.ToBase64String(keyBuffer);

            // Build the config object including the Logging/AllowedHosts you requested
            var config = new
            {
                AdminSettings = new
                {
                    Password = randomAdminPassword
                },
                JwtSettings = new
                {
                    Key = randomKey,
                    Issuer = "MyApp"
                },
                Logging = new
                {
                    LogLevel = new
                    {
                        Default = "Information",
                        Microsoft_AspNetCore = "Warning"
                    }
                },
                AllowedHosts = "*"
            };

            // Write to appsettings.json
            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(appSettingsFile, json);

            Console.WriteLine("Created appsettings.json with AdminSettings:Password, JwtSettings, and Logging defaults.");
        }

        /// <summary>
        /// Helper method to run CLI commands.
        /// </summary>
        private static void RunCommand(string command, string args, string workingDirectory)
        {
            var psi = new ProcessStartInfo
            {
                FileName = command,
                Arguments = args,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };
            proc.OutputDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine(e.Data);
            };
            proc.ErrorDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine("ERROR: " + e.Data);
            };

            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            proc.WaitForExit();
        }
    }
}
