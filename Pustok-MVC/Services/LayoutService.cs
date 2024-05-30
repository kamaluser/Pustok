using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pustok_MVC.Data;
using Pustok_MVC.Models;
using Pustok_MVC.ViewModels;
using System.Security.Claims;

namespace Pustok_MVC.Services
{
    public class LayoutService
    {
        private readonly AppDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LayoutService(AppDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }
        public List<Genre> GetGenres()
        {
            return _context.Genres.ToList();
        }

        public Dictionary<String, String> GetSettings()
        {
            return _context.Settings.ToDictionary(x => x.Key, x => x.Value);
        }

        public BasketViewModel GetBasket()
        {
            BasketViewModel vm = new BasketViewModel
            {
                Items = new List<BasketItemViewModel>()
            };

            if (_httpContextAccessor.HttpContext.User.Identity.IsAuthenticated && _httpContextAccessor.HttpContext.User.IsInRole("member"))
            {
                var userId = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;

                var basketItems = _context.BasketItems
                    .Include(x => x.Book).ThenInclude(b => b.BookImages.Where(bi => bi.PosterStatus == true))
                    .Where(x => x.AppUserId == userId)
                    .ToList();

                vm.Items = basketItems.Select(x => new BasketItemViewModel
                {
                    BookId = x.BookId,
                    BookName = x.Book.Name,
                    BookPrice = (decimal)(x.Book.DiscountPercent > 0 ? (x.Book.SalePrice * (100 - x.Book.DiscountPercent) / 100) : x.Book.SalePrice),
                    BookImage = x.Book.BookImages.FirstOrDefault(x => x.PosterStatus == true)?.Name,
                    Count = x.Count
                }).ToList();

                vm.TotalPrice = vm.Items.Sum(x => x.Count * x.BookPrice);
            }
            else
            {
                var cookieBasket = _httpContextAccessor.HttpContext.Request.Cookies["basket"];

                if (cookieBasket != null)
                {
                    List<BasketCookieItemViewModel> cookieItemsVM = JsonConvert.DeserializeObject<List<BasketCookieItemViewModel>>(cookieBasket);

                    foreach (var cookieItem in cookieItemsVM)
                    {
                        var book = _context.Books.Include(b => b.BookImages.Where(bi => bi.PosterStatus == true)).FirstOrDefault(x => x.Id == cookieItem.BookId && !x.IsDeleted);

                        if (book != null)
                        {
                            BasketItemViewModel itemVM = new BasketItemViewModel
                            {
                                BookId = cookieItem.BookId,
                                BookPrice = (decimal)(book.DiscountPercent > 0 ? (book.SalePrice * (100 - book.DiscountPercent) / 100) : book.SalePrice),
                                BookImage = book.BookImages.FirstOrDefault(x => x.PosterStatus == true)?.Name,
                                Count = cookieItem.Count,
                                BookName = book.Name
                            };
                            vm.Items.Add(itemVM);
                        }
                    }
                    vm.TotalPrice = vm.Items.Sum(x => x.Count * x.BookPrice);
                }
            }
            return vm;
        }




    }
}
