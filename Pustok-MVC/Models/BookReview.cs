using Pustok_MVC.Models.Enums;

namespace Pustok_MVC.Models
{
    public class BookReview
    {
        public int Id { get; set; }
        public int BookId { get; set; }
        public string? AppUserId { get; set; }
        public string Text { get; set; }
        public byte Rate { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public ReviewStatus Status { get; set; } = ReviewStatus.Pending;
        public Book? Book { get; set; }
        public AppUser? AppUser { get; set; }
    }
}
