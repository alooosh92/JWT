using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace JWT.Data.JWT
{
    public class UserModel
    {
        [Required]
        [EmailAddress]
        public string? UserName { get; set; }
        [Required]
        [MinLength(6)]
        public string? Password { get; set; }
        [Required]
        [DefaultValue("User")]
         public string? Role { get; set; }
    }
}
