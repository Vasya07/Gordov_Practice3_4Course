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

app.MapPost("/register", async (RegisterRequest req, BD_WebAPI_Site_Seling_TShirtsContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Login == req.Login))
        return Results.Conflict("Логин уже занят");

    var hasher = new PasswordHasher<User>();
    var user = new User
    {
        Login = req.Login,
        Role = "user",
        TelephoneNumber = req.TelephoneNumber,
        OrderAddress = req.OrderAddress
    };
    user.PasswordHash = hasher.HashPassword(user, req.Password);

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok(new { user.UserId, user.Login });
});

app.MapPost("/login", async (LoginRequest req, BD_WebAPI_Site_Seling_TShirtsContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Login == req.Login);
    if (user is null) return Results.Unauthorized();

    var hasher = new PasswordHasher<User>();
    var result = hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);

    if (result == PasswordVerificationResult.Failed)
        return Results.Unauthorized();

    return Results.Ok(new { token = CreateToken(user) });
});

app.MapGet("/clothes", async (BD_WebAPI_Site_Seling_TShirtsContext db) =>
{
    var items = await db.Clothes
        .AsNoTracking()
        .Where(c => c.IsForSale == 1)
        .Select(c => new
        { 
            c.ClothId,
            c.ItemName,
            c.Price,
            c.ClothType,
            c.Descr,
            c.SellCounter,
            Sizes = c.ClothesSizes.Select(s => new
            {
                s.ClothSizeId,
                s.SizeString,
                s.SizeInt,
                s.QuantityInStock
            })
        })
        .ToListAsync();

    return Results.Ok(items);
});

app.MapPost("/orders", async (CreateOrderRequest req, ClaimsPrincipal principal, BD_WebAPI_Site_Seling_TShirtsContext db) =>
{
    var userId = int.Parse(principal.FindFirst("user_id")!.Value);
    var order = new Order
    {
        CustomerId = userId,
        CreateDatetime = DateTime.UtcNow,
        CurrentOrderStatus = "new",
        CustomerFio = req.CustomerFio
    };

    foreach (var item in req.Items)
    {
        var size = await db.ClothesSizes
            .Include(s => s.Cloth)
            .FirstOrDefaultAsync(s => s.ClothSizeId == item.ClothSizeId);

        if (size is null) return Results.BadRequest($"Размер {item.ClothSizeId} не найден");
        if (size.QuantityInStock < item.Quantity)
            return Results.BadRequest($"Недостаточно товара {size.Cloth.ItemName} ({size.SizeString})");

        size.QuantityInStock -= item.Quantity;
        order.OrderItems.Add(new OrderItem
        {
            ClothSizeId = size.ClothSizeId,
            Quantity = item.Quantity,
            PriceAtMoment = size.Cloth.Price,
            ClothNameSnapshot = size.Cloth.ItemName,
            SizeStringSnapshot = size.SizeString
        });
    }

    db.Orders.Add(order);
    await db.SaveChangesAsync();

    return Results.Ok(new { order.OrderId, Message = "Заказ успешно создан" });
})
.RequireAuthorization();

app.MapGet("/my/orders", async (ClaimsPrincipal principal, BD_WebAPI_Site_Seling_TShirtsContext db) =>
{
    var userId = int.Parse(principal.FindFirst("user_id")!.Value);
    var orders = await db.Orders
        .AsNoTracking()
        .Where(o => o.CustomerId == userId)
        .OrderByDescending(o => o.CreateDatetime)
        .Select(o => new
        {
            o.OrderId,
            o.CreateDatetime,
            o.CurrentOrderStatus,
            o.CustomerFio,
            Items = o.OrderItems.Select(i => new
            {
                i.ClothNameSnapshot,
                i.SizeStringSnapshot,
                i.Quantity,
                i.PriceAtMoment
            })
        })
        .ToListAsync();

    return Results.Ok(orders);
})
.RequireAuthorization();

app.Run();

record LoginRequest(string Login, string Password);
record RegisterRequest(string Login, string Password, string? TelephoneNumber, string? OrderAddress);
record CreateOrderRequest(string CustomerFio, List<CreateOrderItem> Items);
record CreateOrderItem(int ClothSizeId, int Quantity);