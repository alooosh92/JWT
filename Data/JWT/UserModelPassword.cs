using System.ComponentModel.DataAnnotations;

namespace JWT.Data.JWT
{
    public class UserModelPassword
    {
        [Required]
        [EmailAddress]
        public string? UserName { get; set; }
        [Required]
        [MinLength(6)]
        public string? OldPassword { get; set; }
        [Required]
        [MinLength(6)]
        public string? NewPassword { get; set; }
    }
}
