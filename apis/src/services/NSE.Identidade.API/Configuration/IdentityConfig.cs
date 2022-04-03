using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Data;
using NSE.Identidade.API.Extensions;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace NSE.Identidade.API.Configuration
{
    public static class IdentityConfig
    {
        public static void AddIdentity(this WebApplicationBuilder builder)
        {
            builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddErrorDescriber<IdentityErrors>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var configSection = builder.Configuration.GetSection(nameof(JwtSettings));
            builder.Services.Configure<JwtSettings>(configSection);
            var jwtSettings = configSection.Get<JwtSettings>();

            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidAudience = jwtSettings.ValidAudience,
                        ValidIssuer = jwtSettings.ValidIssuer,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret))
                    };
                });
        }

        public static IApplicationBuilder UseIdentity(this WebApplication app)
        {
            app.UseAuthentication();
            app.UseAuthorization();

            return app;
        }
    }
}
