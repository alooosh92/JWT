using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace JWT.Data.JWT
{
    public class AuthServies :IAuthServies
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOptions<JWTValues> _jwt;
        private readonly IEmailSender _emailSender;
        private readonly ApplicationDbContext _db;
        public AuthServies(UserManager<IdentityUser> userManager, IOptions<JWTValues> jwt, IEmailSender emailSender, ApplicationDbContext db)
        {
            _userManager = userManager;
            _jwt = jwt;
            _emailSender = emailSender;
            _db = db;
        }
        private async Task<JwtSecurityToken> CreateJwtSecurityToken(IdentityUser identityUser)
        {
            var userClaims = await _userManager.GetClaimsAsync(identityUser);
            var roles = await _userManager.GetRolesAsync(identityUser);
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,identityUser.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim("uid",identityUser.Id)
            }.Union(userClaims).Union(roleClaims);
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Value.Key!));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Value.Issuer,
                audience: _jwt.Value.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.Value.DurationInDays).ToLocalTime(),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }
        private RefreshToken GeneraterRefreshToken(string userId)
        {
            var randomNumber = new byte[32];
            using var genertor = new RNGCryptoServiceProvider();
            genertor.GetBytes(randomNumber);
            return new RefreshToken
            {
                UserId = userId, 
                CreatedOn = DateTime.UtcNow,
                Expirson = DateTime.UtcNow.AddDays(1),
                Id = Guid.NewGuid().ToString(),
                Token = Convert.ToBase64String(randomNumber),
            };
        }
        public async Task<ActionResult<AuthModel>> Register(UserModel userModel)
        {
            if (userModel.UserName == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var u = await _userManager.FindByEmailAsync(userModel.UserName!);
            if (u is not null) { return new AuthModel { Message = "The email is uses" }; }                       
            var user = new IdentityUser
            {
                UserName = userModel.UserName!,
                Email = userModel.UserName!,
                EmailConfirmed = true
            };
            var res = await _userManager.CreateAsync(user, userModel.Password!);
            if (!res.Succeeded) { return new AuthModel { Message = "Error"}; }
            var newUser = await _userManager.FindByEmailAsync(user.Email);
            var refreshToken = GeneraterRefreshToken(newUser!.Id);
            await _db.RefreshTokens.AddAsync(refreshToken);
            if (!res.Succeeded) { return new AuthModel { Message = "Error in Create User" }; }
            await _userManager.AddToRoleAsync(user, "User");
            var token = await CreateJwtSecurityToken(user);            
            await _userManager.UpdateAsync(user);
            var back = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.UserName!,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpireson = refreshToken.Expirson
            };
            return back;
        }
        public async Task<ActionResult<AuthModel>> Login(UserModel userModel)
        {
            if (userModel.UserName == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var user = await _userManager.FindByEmailAsync(userModel.UserName);
            if (user == null || !await _userManager.CheckPasswordAsync(user, userModel.Password)) { return new AuthModel { Message = "username or password is Wrong" }; }
            var token = await CreateJwtSecurityToken(user);           
            RefreshToken oldRefreshToken = _db.RefreshTokens.SingleOrDefault(r=>r.UserId == user.Id && r.RevokedON == null && DateTime.UtcNow >= r.Expirson)!;
            if (oldRefreshToken != null) {
                await RevokeToken(oldRefreshToken.Token!);
            }
            var refreshToken = GeneraterRefreshToken(user.Id);
            _db.RefreshTokens!.Add(refreshToken);
            _db.SaveChanges();
            var rutToken = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpireson = refreshToken.Expirson
            };
          /*
           if (await _db.RefreshTokens!.AnyAsync(t =>t.UserId == user.Id && t.IsActive)) 
            {
                var activeRefreshToken = await _db.RefreshTokens!.SingleOrDefaultAsync(t => t.UserId == user.Id && t.IsActive);
                rutToken.RefreshToken = activeRefreshToken!.Token;
                rutToken.RefreshTokenExpireson = activeRefreshToken.Expirson;
            }else
            {
                var refrehsToken = GeneraterRefreshToken(user.Id);
                rutToken.RefreshToken = refrehsToken.Token;
                rutToken.RefreshTokenExpireson = refrehsToken.Expirson;               
                await _db.RefreshTokens!.AddAsync(refrehsToken);
                await _userManager.UpdateAsync(user);
            }*/
            return rutToken;

        }
        public async Task<ActionResult<AuthModel>> ChangePassword(UserModelPassword userModel)
        {
            var user = await _userManager.FindByNameAsync(userModel.UserName!);
            if (user == null) return new AuthModel { Message = "Error" };
            var res = await _userManager.ChangePasswordAsync(user,
                userModel.OldPassword!, userModel.NewPassword!);
            if (!res.Succeeded) return new AuthModel { Message = "something is Error" };
            return new AuthModel { Message = "Succeeded Change Password" };
        }
        public async Task<ActionResult<AuthModel>> ForgetPassword(UserModel userModel)
        {
            if (userModel.UserName == null) return new AuthModel { Message = "Email is null" };
            var user = await _userManager.FindByEmailAsync(userModel.UserName);
            if (user == null) return new AuthModel { Message = "User not find" };
            var newPass = Guid.NewGuid().ToString().Substring(0, 8);
            var rest = await _userManager.ResetPasswordAsync(user, await _userManager.GeneratePasswordResetTokenAsync(user), newPass);
            if (rest.Succeeded) await _emailSender.SendEmailAsync(userModel.UserName!, "Rest password", $"كلمة السر الجديدة: {newPass}");
            return new AuthModel { Message = "Password reset plase check email" };
        }
        public async Task<ActionResult<AuthModel>> RefreshToken(string token)
        {
            var authModel = new AuthModel();
            var tok = await _db.RefreshTokens.SingleOrDefaultAsync(r=>r.Token == token);
            if(tok == null)
            {
                authModel.Message = "InValid token";
                return authModel;
            }
            if (!(tok.RevokedON == null && DateTime.UtcNow <= tok.Expirson))
            {
                authModel.Message = "Inactive token";
                return authModel;
            }
            tok.RevokedON = DateTime.UtcNow;
            var newRefreshToken = GeneraterRefreshToken(tok.UserId!);         
            await _db.RefreshTokens!.AddAsync(newRefreshToken);
            _db.RefreshTokens.Update(tok);
            await _db.SaveChangesAsync();
            var user = await _userManager.FindByIdAsync(tok.UserId!);
            var jwtToken = await CreateJwtSecurityToken(user!);
            authModel.IsAuthanticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user!.Email;
            var roles = await _userManager.GetRolesAsync(user);
            authModel.Roles = roles.ToList();
            authModel.RefreshToken = newRefreshToken.Token;
            authModel.RefreshTokenExpireson = newRefreshToken.Expirson;
            return authModel;
        }
        public async Task<bool> RevokeToken(string token)
        {
            var toke = await _db.RefreshTokens.SingleOrDefaultAsync(t=>t.Token == token);
            if (toke == null) return false;   
            if (!(toke.RevokedON == null && DateTime.UtcNow <= toke.Expirson)) return false;
            toke.RevokedON = DateTime.UtcNow;
            _db.RefreshTokens.Update(toke);
            await _db.SaveChangesAsync();
            return true;
        }
    }
}
