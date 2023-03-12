using Microsoft.AspNetCore.Mvc;

namespace JWT.Data.JWT
{
    public interface IAuthServies
    {
        Task<ActionResult<AuthModel>> Register(UserModel userModel);
        Task<ActionResult<AuthModel>> Login(UserModel userModel);
        Task<ActionResult<AuthModel>> ForgetPassword(UserModel userModel);
        Task<ActionResult<AuthModel>> ChangePassword(UserModelPassword userModel);
    }
}
