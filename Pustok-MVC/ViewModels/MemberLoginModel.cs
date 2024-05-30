using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class MemberLoginModel
    {
        [MaxLength(25)]
        [MinLength(5)]
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [MaxLength(25)]
        [MinLength(8)]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
