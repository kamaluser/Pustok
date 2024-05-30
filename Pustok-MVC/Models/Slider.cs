using Pustok_MVC.Attributes;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok_MVC.Models
{
    public class Slider
    {
        public int Id { get; set; }
        [MaxLength(100)]
        public string? Title1 { get; set; }
        [MaxLength(100)]
        public string? Title2 { get; set; }
        public string? BtnText { get; set; }
        public string? BtnUrl { get; set; }
        [MaxLength(250)]
        public string? Desc { get; set; }
        public string? Image { get; set; }
        public int Order { get; set; }
        [NotMapped]
        [MaxSize(2*1024*1024)]
        [CheckImageContent("image/png","image/jpeg")]
        public IFormFile? ImageFile { get; set; }
    }
}
