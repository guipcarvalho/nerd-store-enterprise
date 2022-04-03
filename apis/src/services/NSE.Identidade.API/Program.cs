using NSE.Identidade.API.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddApiConfig();
builder.Services.AddSwagger();

builder.AddIdentity();

var app = builder.Build();

app.UseApiConfig();

app.Run();
