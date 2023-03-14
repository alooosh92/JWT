 using JWT.Data;
 using Microsoft.AspNetCore.Authentication.JwtBearer;
 using Microsoft.AspNetCore.Identity;
 using Microsoft.EntityFrameworkCore;
 using Microsoft.IdentityModel.Tokens;
 using System.Text;
 using JWT.Data.JWT;
 using Microsoft.AspNetCore.Identity.UI.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
//jwt code
builder.Services.Configure<JWTValues>(builder.Configuration.GetSection("JWT"));
builder.Services.AddDbContext<ApplicationDbContext>(
    opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; 
}).AddJwtBearer(opt => {
    opt.RequireHttpsMetadata = false;
    opt.SaveToken = false;
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["JWT:Issuer"],
        ValidAudience = builder.Configuration["JWT:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]!))
    };
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>(opt =>
{
    //SingIn
    opt.SignIn.RequireConfirmedEmail = false;
    opt.SignIn.RequireConfirmedPhoneNumber = false;
    opt.SignIn.RequireConfirmedAccount = false;
    //Password
    opt.Password.RequireDigit = false;
    opt.Password.RequiredLength = 6;
    opt.Password.RequiredUniqueChars = 0;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequireUppercase = false;
    opt.Password.RequireLowercase = false;
}).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
builder.Services.AddTransient<IAuthServies, AuthServies>();
builder.Services.AddTransient<IEmailSender, EmailSender>(a =>
              new EmailSender(
                  builder.Configuration["EmailSender:Host"]!,
                  builder.Configuration.GetValue<int>("EmailSender:Port"),
                  builder.Configuration.GetValue<bool>("EmailSender:EnableSSL"),
                  builder.Configuration["EmailSender:UserName"]!,
                  builder.Configuration["EmailSender:Password"]!
              )
          );
//jwt code
var app = builder.Build();
//if (app.Environment.IsDevelopment())
//{
    app.UseSwagger();
    app.UseSwaggerUI();
//}
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
//JWT Add defulte role and user admin
await AddDatabaseItem.AddRoll(app.Services, new List<string> { "User", "Admin", "Employee" });
await AddDatabaseItem.AddAdmin(app.Services, builder.Configuration["EmailSender:UserName"]!);
//JWT
app.Run();
