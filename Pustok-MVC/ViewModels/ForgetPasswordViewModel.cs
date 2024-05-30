using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class ForgetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [MinLength(5)]
        [MaxLength(100)]
        public string Email { get; set; }
    }
}
