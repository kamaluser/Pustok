using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class MyAccountViewModel
    {
        public string UserName { get; set; }
        public string FullName { get; set; }
        [MaxLength(35)]
        [EmailAddress]
        public string Email { get; set; }

        [NotMapped]
        [MinLength(8)]
        [MaxLength(25)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [NotMapped]
        [MinLength(8)]
        [MaxLength(25)]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmedPassword { get; set; }

        [NotMapped]
        [MaxLength(25)]
        [MinLength(8)]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        
    }
}
