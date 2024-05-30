using Pustok_MVC.Models;

namespace Pustok_MVC.ViewModels
{
    public class ShopViewModel
    {
        public List<Genre> Genres { get; set; }
        public List<Author> Authors { get; set; }
        public List<Book> Books { get; set; }
        public int CurrentPage { get; set; }
        public int TotalPages { get; set; }
    }
}
