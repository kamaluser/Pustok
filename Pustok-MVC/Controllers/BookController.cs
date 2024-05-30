using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using NuGet.ProjectModel;
using Pustok_MVC.Data;
using Pustok_MVC.Models;
using Pustok_MVC.ViewModels;
using System.Security.Claims;

namespace Pustok_MVC.Controllers
{
    public class BookController : Controller
    {
        private readonly AppDbContext _context;
        private readonly UserManager<AppUser> _userManager;

        public BookController(AppDbContext context, UserManager<AppUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }
        public IActionResult GetBookById(int id)
        {
            Book book = _context.Books.Include(x => x.Genre).Include(x => x.BookImages.Where(x => x.PosterStatus == true)).FirstOrDefault(x => x.Id == id);
            return PartialView("_BookModalContentPartial", book);
        }

        public IActionResult Detail(int id)
        {
            var vm = getBookDetailVM(id);

            if (vm.Book == null) return RedirectToAction("notfound", "error");

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Review(BookReview review)
        {
            AppUser? user = await _userManager.GetUserAsync(User);

            if (user == null || !await _userManager.IsInRoleAsync(user, "member"))
            {
                return RedirectToAction("login", "account", new { returnUrl = Url.Action("detail", "book", new { id = review.BookId }) });
            }

            if (!_context.Books.Any(x => x.Id == review.BookId && !x.IsDeleted))
            {
                return RedirectToAction("notfound", "error");
            }

            if (_context.BookReviews.Any(x => x.Id == review.BookId && x.AppUserId == user.Id))
            {
                return RedirectToAction("notfound", "error");
            }

            if (!ModelState.IsValid)
            {
                var vm = getBookDetailVM(review.BookId);
                vm.Review = review;
                return View("detail", vm);
            }

            review.AppUserId = user.Id;
            review.CreatedAt = DateTime.Now;

            _context.BookReviews.Add(review);
            _context.SaveChanges();

            return RedirectToAction("Detail", new { id = review.BookId });
        }


        public async Task<IActionResult> GetMoreReviews(int bookId, int skip, int take)
        {
            var reviews = await _context.BookReviews
                .Where(x => x.BookId == bookId && x.Status != Models.Enums.ReviewStatus.Accepted)
                .Include(r => r.AppUser)
                .OrderByDescending(r => r.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync();
            return Json(reviews);
        }
        private BookDetailViewModel getBookDetailVM(int bookId)
        {


            Book? book = _context.Books
              .Include(x => x.Genre)
              .Include(x => x.Author)
              .Include(x => x.BookImages)
              .Include(x => x.BookReviews).ThenInclude(r => r.AppUser)
              .Include(x => x.BookTags).ThenInclude(bt => bt.Tag)
              .FirstOrDefault(x => x.Id == bookId && !x.IsDeleted);

            if (book == null)
            {
                return null;
            }

            int totalCommentPage = book.BookReviews?.Count() ?? 0;
            ViewBag.TotalCommentPage = totalCommentPage > 0 ? Math.Ceiling(totalCommentPage / 2m) : 0;


            BookDetailViewModel vm = new BookDetailViewModel
            {
                Book = book,
                RelatedBooks = _context.Books
                       .Include(x => x.Author)
                       .Include(x => x.BookImages
                               .Where(bi => bi.PosterStatus != null))
                       .Where(x => book != null && x.GenreId == book.GenreId)
                       .Take(5).ToList(),
                Review = new BookReview { BookId = bookId }
            };

            AppUser? user = _userManager.GetUserAsync(User).Result;

            if (user == null)
            {

                return vm;
            }
            if (_userManager.IsInRoleAsync(user, "member").Result && _context.BookReviews.Any(x => x.BookId == bookId && x.AppUserId == user.Id && x.Status != Models.Enums.ReviewStatus.Rejected))
            {
                vm.HasUserReview = true;
            }

            vm.TotalReviewsCount = _context.BookReviews.Count(x => x.BookId == bookId && x.Status == Models.Enums.ReviewStatus.Accepted);
            vm.AvgRate = vm.TotalReviewsCount > 0 ? (int)Math.Ceiling(_context.BookReviews.Where(x => x.BookId == bookId && x.Status == Models.Enums.ReviewStatus.Accepted).Average(x => x.Rate)) : 0;

            return vm;
        }


        public IActionResult LoadReview(int id, int page = 1)
        {
            List<BookReview> comments = _context.BookReviews.Include(x => x.AppUser).Where(x => x.BookId == id).OrderByDescending(x => x.CreatedAt).Skip((page - 1) * 2).Take(2).ToList();

            return PartialView("_BookReviews", comments);
        }
        public IActionResult AddToBasket(int bookId)
        {
            if (User.Identity.IsAuthenticated && User.IsInRole("member"))
            {
                string userId = User.FindFirst(ClaimTypes.NameIdentifier).Value;

                Book book = _context.Books.FirstOrDefault(x => x.Id == bookId && !x.IsDeleted);
                if (book == null)
                {
                    return RedirectToAction("notfound", "error");
                }

                BasketItem basketItem = _context.BasketItems.FirstOrDefault(x => x.BookId == bookId && x.AppUserId == userId);

                if (basketItem == null)
                {
                    basketItem = new BasketItem
                    {
                        AppUserId = userId,
                        BookId = bookId,
                        Count = 1
                    };
                    _context.BasketItems.Add(basketItem);
                }
                else
                {
                    basketItem.Count++;
                }

                _context.SaveChanges();
                return PartialView("_BasketPartial", getBasket());
            }
            else
            {
                List<BasketCookieItemViewModel> basketItems;

                var cookieItem = Request.Cookies["basket"];

                if (cookieItem != null)
                {
                    basketItems = JsonConvert.DeserializeObject<List<BasketCookieItemViewModel>>(cookieItem);
                }
                else
                {
                    basketItems = new List<BasketCookieItemViewModel>();
                }

                BasketCookieItemViewModel item = basketItems.FirstOrDefault(x => x.BookId == bookId);

                if (item == null)
                {
                    item = new BasketCookieItemViewModel
                    {
                        BookId = bookId,
                        Count = 1
                    };
                    basketItems.Add(item);
                }
                else
                {
                    item.Count++;
                }

                Response.Cookies.Append("basket", JsonConvert.SerializeObject(basketItems), new CookieOptions
                {
                    Expires = DateTime.Now.AddDays(30)
                });

                Response.Cookies.Append("basket", JsonConvert.SerializeObject(basketItems));
                return PartialView("_BasketPartial", getBasket(basketItems));   
            }
        }


        //[HttpPost]
        [AutoValidateAntiforgeryToken]
        public IActionResult RemoveFromBasket(int bookId)
        {
            if (User.Identity.IsAuthenticated && User.IsInRole("member"))
            {
                string userId = User.FindFirst(ClaimTypes.NameIdentifier).Value;

                BasketItem basketItem = _context.BasketItems.FirstOrDefault(x => x.BookId == bookId && x.AppUserId == userId);

                if (basketItem != null)
                {
                    _context.BasketItems.Remove(basketItem);
                    _context.SaveChanges();
                }
            }
            else
            {
                var cookieBasket = Request.Cookies["basket"];
                if (cookieBasket != null)
                {
                    List<BasketCookieItemViewModel> cookieItems = JsonConvert.DeserializeObject<List<BasketCookieItemViewModel>>(cookieBasket);
                    var itemToRemove = cookieItems.FirstOrDefault(x => x.BookId == bookId);

                    if (itemToRemove != null)
                    {
                        cookieItems.Remove(itemToRemove);
                        Response.Cookies.Append("basket", JsonConvert.SerializeObject(cookieItems));
                    }
                }
            }

            return RedirectToAction("index","home");

        }


        private BasketViewModel getBasket(List<BasketCookieItemViewModel>? items = null)
        {
            BasketViewModel vm = new BasketViewModel();

            if (User.Identity.IsAuthenticated && User.IsInRole("member"))
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier).Value;

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
                if (items != null)
                {
                    foreach (var cookieItem in items)
                    {
                        Book? book = _context.Books.Include(x => x.BookImages.Where(bi => bi.PosterStatus == true)).FirstOrDefault(x => x.Id == cookieItem.BookId && !x.IsDeleted);

                        if (book != null)
                        {
                            BasketItemViewModel itemVM = new BasketItemViewModel
                            {
                                BookId = cookieItem.BookId,
                                Count = cookieItem.Count,
                                BookName = book.Name,
                                BookPrice = (decimal)(book.DiscountPercent > 0 ? (book.SalePrice * (100 - book.DiscountPercent) / 100) : book.SalePrice),
                                BookImage = book.BookImages.FirstOrDefault(x => x.PosterStatus == true)?.Name
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