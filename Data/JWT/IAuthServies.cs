using Microsoft.AspNetCore.Mvc;

namespace JWT.Data.JWT
{
    public interface IAuthServies
    {
        Task<ActionResult<AuthModel>> Register(UserModel userModel);
        Task<ActionResult<AuthModel>> Login(UserModel userModel);
        Task<ActionResult<bool>> ForgetPassword(string username);
        Task<ActionResult<AuthModel>> ChangePassword(UserModelPassword userModel);
        Task<ActionResult<AuthModel>> RefreshToken(string token);
        Task<bool> RevokeToken(string token);
    }
}
