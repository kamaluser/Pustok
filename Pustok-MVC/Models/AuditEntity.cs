namespace Pustok_MVC.Models
{
    public class AuditEntity
    {
        public DateTime? CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ModifiedAt { get; set; }
        public bool IsDeleted { get; set; }
    }
}
