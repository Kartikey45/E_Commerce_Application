using AuthenticatedWebAPI.Data;
using AuthenticatedWebAPI.Models;
using AuthenticatedWebAPI.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace AuthenticatedWebAPI.Extensions
{
    public static class ServiceExtensions
    {
        /// <summary>
        /// Register database and Entity Framework Core services
        /// </summary>
        public static IServiceCollection AddDatabaseServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("Default")));

            return services;
        }

        /// <summary>
        /// Register Identity services with custom options
        /// </summary>
        public static IServiceCollection AddIdentityServices(this IServiceCollection services)
        {
            services.AddIdentity<User, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                options.SignIn.RequireConfirmedEmail = true;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 3;
                /*  
                options.Lockout.AllowedForNewUsers = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = true;
                */
            });

            services.Configure<DataProtectionTokenProviderOptions>(o =>
                o.TokenLifespan = TimeSpan.FromHours(5));

            return services;
        }

        /// <summary>
        /// Register JWT Bearer authentication with validation
        /// </summary>
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtKey = configuration["Jwt:Key"];
            var jwtIssuer = configuration["Jwt:Issuer"];
            var jwtAudience = configuration["Jwt:Audience"];

            if (string.IsNullOrWhiteSpace(jwtKey) ||
                string.IsNullOrWhiteSpace(jwtIssuer) ||
                string.IsNullOrWhiteSpace(jwtAudience))
            {
                throw new InvalidOperationException(
                    "JWT configuration is missing. Ensure Jwt:Key, Jwt:Issuer, and Jwt:Audience are set in configuration.");
            }

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtIssuer,
                    ValidAudience = jwtAudience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                    //ClockSkew = TimeSpan.FromMinutes(5)
                };
            });

            return services;
        }

        /// <summary>
        /// Register authorization services
        /// </summary>
        public static IServiceCollection AddAuthorizationServices(this IServiceCollection services)
        {
            services.AddAuthorization();
            return services;
        }

        /// <summary>
        /// Register Swagger/OpenAPI services with JWT Bearer configuration
        /// </summary>
        public static IServiceCollection AddSwaggerServices(this IServiceCollection services)
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(options =>
            {
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Enter your JWT token in the format: Bearer {your token}"
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            return services;
        }

        /// <summary>
        /// Register application-specific services (User, Email, Token)
        /// </summary>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IUserClaimsPrincipalFactory<User>, ApplicationUserClaimsPricipalFactory>();
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<ITokenService, TokenService>();

            services.Configure<SMTPConfigModel>(configuration.GetSection("SMTPConfig"));

            return services;
        }

        /// <summary>
        /// Register CORS policy for React frontend
        /// </summary>
        public static IServiceCollection AddCorsServices(this IServiceCollection services, IConfiguration configuration)
        {
            var reactAppUrl = configuration["CORS:ReactAppUrl"] ?? "http://localhost:3000";

            services.AddCors(options =>
            {
                options.AddPolicy("ReactPolicy", builder =>
                {
                    builder
                        .WithOrigins(reactAppUrl)
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
            });

            return services;
        }
    }
}