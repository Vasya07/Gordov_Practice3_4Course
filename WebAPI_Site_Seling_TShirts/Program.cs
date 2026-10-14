using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using WebAPI_Site_Seling_TShirts.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<BD_WebAPI_Site_Seling_TShirtsContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

var jwtKey = builder.Configuration["Jwt:Key"]!;
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

var validation = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidateAudience = true,
    ValidAudience = builder.Configuration["Jwt:Audience"],
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = key,
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,
    NameClaimType = "name",
    RoleClaimType = "role"
};

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = validation;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

string CreateToken(User user)
{
    var claims = new[]
    {
        new Claim("user_id", user.UserId.ToString()),
        new Claim("name", user.Login),
        new Claim("role", user.Role)
    };

    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(15),
        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

    return new JwtSecurityTokenHandler().WriteToken(token);
}
