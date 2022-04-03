namespace NSE.Identidade.API.Configuration
{
    public static class ApiConfig
    {
        public static IServiceCollection AddApiConfig(this IServiceCollection services)
        {
            services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();

            return services;
        }

        public static WebApplication UseApiConfig(this WebApplication app)
        {
            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwaggerConfig();
            }

            app.UseHttpsRedirection();

            app.UseIdentity();

            app.MapControllers();

            return app;
        }
    }
}
