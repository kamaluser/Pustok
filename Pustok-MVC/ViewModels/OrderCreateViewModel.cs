using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.ViewModels
{
    public class OrderCreateViewModel
    {
        [Required(ErrorMessage = "Address Is Required!")]
        [MaxLength(250)]
        public string Address { get; set; }
        [Required]
        [MaxLength(30)]
        public string Phone { get; set; }
        [MaxLength(500)]
        public string? Note { get; set; }
    }
}
