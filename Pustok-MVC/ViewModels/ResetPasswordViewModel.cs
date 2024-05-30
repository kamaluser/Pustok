using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class ResetPasswordViewModel
    {
        [MaxLength(25)]
        [MinLength(8)]
        [DataType(DataType.Password)]
        public string? NewPassword { get; set; }
        [MaxLength(25)]
        [MinLength(8)]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword))]
        public string? ConfirmNewPassword { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
    }
}
