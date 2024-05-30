namespace Pustok_MVC.Models
{
    public class Author:AuditEntity
    {
        public int Id { get; set; }
        public string Fullname { get; set; }
        public List<Book>? Books { get; set; }
    }
}
