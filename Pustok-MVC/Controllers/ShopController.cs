using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Pustok_MVC.Data;
using Pustok_MVC.ViewModels;

namespace Pustok_MVC.Controllers
{
    public class ShopController : Controller
    {
        private readonly AppDbContext _context;
        private const int PageSize = 9; 

        public ShopController(AppDbContext context)
        {
            _context = context;
        }

        public IActionResult Index(int? genreId = null, List<int>? authorIds = null, double? minPrice = null, double? maxPrice = null, string sort = "AToZ", int page = 1)
        {
            var vm = new ShopViewModel
            {
                Authors = _context.Authors.Include(x => x.Books).ToList(),
                Genres = _context.Genres.Include(x => x.Books).ToList(),
            };

            var query = _context.Books
                                .Include(x => x.BookImages.Where(bi => bi.PosterStatus != null))
                                .Include(x => x.Author)
                                .AsQueryable();

            if (genreId.HasValue)
            {
                query = query.Where(x => x.GenreId == genreId.Value);
            }
            if (authorIds != null && authorIds.Count > 0)
            {
                query = query.Where(x => authorIds.Contains(x.AuthorId));
            }
            if (minPrice.HasValue && maxPrice.HasValue)
            {
                query = query.Where(x => x.SalePrice >= minPrice.Value && x.SalePrice <= maxPrice.Value);
            }

            switch (sort)
            {
                case "ZToA":
                    query = query.OrderByDescending(x => x.Name);
                    break;
                case "HighToLow":
                    query = query.OrderByDescending(x => x.SalePrice);
                    break;
                case "LowToHigh":
                    query = query.OrderBy(x => x.SalePrice);
                    break;
                default:
                    query = query.OrderBy(x => x.Name);
                    break;
            }


            var totalItems = query.Count();
            var totalPages = (int)Math.Ceiling(totalItems / (double)PageSize);

            vm.Books = query.Skip((page - 1) * PageSize).Take(PageSize).ToList();
            vm.CurrentPage = page;
            vm.TotalPages = totalPages;

            ViewBag.GenreId = genreId;
            ViewBag.AuthorIds = authorIds;
            ViewBag.MinPrice = _context.Books.Where(x => !x.IsDeleted).Min(x => x.SalePrice);
            ViewBag.MaxPrice = _context.Books.Where(x => !x.IsDeleted).Max(x => x.SalePrice);
            ViewBag.SelectedMinPrice = minPrice ?? ViewBag.MinPrice;
            ViewBag.SelectedMaxPrice = maxPrice ?? ViewBag.MaxPrice;
            ViewBag.Sort = sort;
            ViewBag.SortItems = new List<SelectListItem>
            {
                new SelectListItem("Default Sorting (A - Z)","AToZ",sort=="AToZ"),
                new SelectListItem("Sort By:Name (Z - A)","ZToA",sort == "ZToA"),
                new SelectListItem("Sort By:Price (Low &gt; High)","LowToHigh",sort == "LowToHigh"),
                new SelectListItem("Sort By:Price (High &gt; Low)","HighToLow",sort == "HighToLow")
            };

            return View(vm);
        }
    }
}
