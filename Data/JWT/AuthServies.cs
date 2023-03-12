using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.Data.JWT
{
    public class AuthServies :IAuthServies
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOptions<JWTValues> _jwt;
        private readonly IEmailSender _emailSender;
        public AuthServies(UserManager<IdentityUser> userManager, IOptions<JWTValues> jwt, IEmailSender emailSender)
        {
            _userManager = userManager;
            _jwt = jwt;
            _emailSender = emailSender;
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
        public async Task<ActionResult<AuthModel>> Register(UserModel userModel)
        {
            if (userModel.UserName == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var u = await _userManager.FindByEmailAsync(userModel.UserName!);
            if (u is not null) { return new AuthModel { Message = "The email is uses" }; }
            var user = new IdentityUser
            {
                UserName = userModel.UserName!,
                Email = userModel.UserName!,
                EmailConfirmed = true,
            };
            var res = await _userManager.CreateAsync(user, userModel.Password!);
            if (!res.Succeeded) { return new AuthModel { Message = "Error in Create User" }; }
            await _userManager.AddToRoleAsync(user, "User");
            var token = await CreateJwtSecurityToken(user);
            var back = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expireson = token.ValidTo.ToLocalTime(),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.UserName!,
            };
            return back;
        }
        public async Task<ActionResult<AuthModel>> Login(UserModel userModel)
        {
            if (userModel.UserName == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var user = await _userManager.FindByNameAsync(userModel.UserName);
            if (user == null || !await _userManager.CheckPasswordAsync(user, userModel.Password)) { return new AuthModel { Message = "username or password is Wrong" }; }
            var token = await CreateJwtSecurityToken(user);
            var rutToken = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expireson = token.ValidTo.ToLocalTime(),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.UserName,
            };
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
    }
}
