using Microsoft.OpenApi.Models;

namespace NSE.Identidade.API.Configuration
{
    public static class SwaggerConfig
    {
        public static IServiceCollection AddSwagger(this IServiceCollection services)
        {
            return services.AddSwaggerGen(c =>
                 {

                     c.SwaggerDoc("v1",
                         new OpenApiInfo
                         {
                             Title = "NerdStore Enterprise",
                             Version = "v1",
                             Description = "API REST feita no curso do Eduardo pires.",
                             Contact = new OpenApiContact
                             {
                                 Name = "Guilherme Carvalho",
                                 Url = new Uri("https://github.com/guipcarvalho")
                             }
                         });
                     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                     {
                         Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
                         Name = "Authorization",
                         In = ParameterLocation.Header,
                         Type = SecuritySchemeType.ApiKey,
                         Scheme = "Bearer"
                     });

                     c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                        {
                            {
                                new OpenApiSecurityScheme
                                {
                                    Reference = new OpenApiReference
                                    {
                                        Type = ReferenceType.SecurityScheme,
                                        Id = "Bearer"
                                    },
                                    Scheme = "oauth2",
                                    Name = "Bearer",
                                    In = ParameterLocation.Header,

                                },
                                new List<string>()
                            }
                        });
                 });
        }

        public static IApplicationBuilder UseSwaggerConfig(this IApplicationBuilder app)
        {
            app.UseSwagger();
            app.UseSwaggerUI();
            return app;
        }

        
    }
}
