using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.Models
{
    public class Genre:AuditEntity
    {
        public int Id { get; set; }
        [MaxLength(20)]
        public string Name { get; set; }
        public List<Book>? Books { get; set; }
    }
}
