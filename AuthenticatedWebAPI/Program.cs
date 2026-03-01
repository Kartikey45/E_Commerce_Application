using AuthenticatedWebAPI.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddDatabaseServices(builder.Configuration);
builder.Services.AddIdentityServices();
builder.Services.AddJwtAuthentication(builder.Configuration);
builder.Services.AddAuthorizationServices();
builder.Services.AddSwaggerServices();
builder.Services.AddApplicationServices(builder.Configuration);
builder.Services.AddCorsServices(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("ReactPolicy");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();