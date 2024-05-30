using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.Models
{
    public class BookImage
    {
        public int Id { get; set; }
        public int BookId { get; set; }
        [Required]
        [MaxLength(250)]
        public string Name { get; set; }
        public bool? PosterStatus { get; set; }
        public Book? Book { get; set; }
    }
}
