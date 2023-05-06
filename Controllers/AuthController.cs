using JWT.Data.JWT;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServies _authServies; 
        public AuthController(IAuthServies authServies) 
        {
            _authServies = authServies;
        }
       [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<AuthModel>> Register([FromBody]UserModel userModel) 
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.Register(userModel);
        }
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<AuthModel>> Login([FromBody] UserModel userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.Login(userModel);
        }
        [HttpPost]
        [Route("ChangePassword")]
        public async Task<ActionResult<AuthModel>> ChangePassword([FromBody] UserModelPassword userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.ChangePassword(userModel);
        }
        [HttpPost]
        [Route("ForgetPassword")]
        public async Task<ActionResult<bool>> ForgetPassword([FromBody] string username)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.ForgetPassword(username);
        }
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<ActionResult<AuthModel>> RefreshToken([FromBody] string refToken)
        {
           return await _authServies.RefreshToken(refToken);
        }
        [HttpPost]
        [Route("RevokeToken")]
        public async Task<bool> RevokeToken([FromBody] string token)
        {
            return await _authServies.RevokeToken(token);
        }
        [HttpGet]
        [Route("CheckToken")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public bool CheckToken()
        {
            return true;
        }
    }
}
