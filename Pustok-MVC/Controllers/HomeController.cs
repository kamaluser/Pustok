using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok_MVC.Data;
using Pustok_MVC.ViewModels;
using System.Diagnostics;

namespace Pustok_MVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _context;
        public HomeController(AppDbContext context)
        {
            _context = context;
        }
        public IActionResult Index()
        {
            HomeViewModel vm = new HomeViewModel()
            {
                Features = _context.Features.ToList(),
                Sliders = _context.Sliders.ToList(),
                FeaturedBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages.Where(bi => bi.PosterStatus != null)).Where(x => x.IsFeatured).Take(10).ToList(),
                NewBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages.Where(bi => bi.PosterStatus != null)).Where(x => x.IsNew).Take(10).ToList(),
                DiscountedBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages.Where(bi => bi.PosterStatus != null)).Where(x => x.DiscountPercent > 0).OrderByDescending(x => x.DiscountPercent).Take(10).ToList(),
            };
            return View(vm);
        }
    }
}