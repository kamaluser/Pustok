using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class MemberRegisterViewModel
    {
        [MaxLength(25)]
        [MinLength(5)]
        [Required]
        public string UserName { get; set; }
        [MaxLength(25)]
        [MinLength(5)]
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [MaxLength(50)]
        [MinLength(5)]
        [Required]
        public string FullName { get; set; }
        [MaxLength(25)]
        [MinLength(8)]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [MaxLength(25)]
        [MinLength(8)]
        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
    }
}
