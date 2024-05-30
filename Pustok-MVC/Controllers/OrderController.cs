using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pustok_MVC.Data;
using Pustok_MVC.Models;
using Pustok_MVC.ViewModels;
using System.Security.Claims;

namespace Pustok_MVC.Controllers
{
    public class OrderController : Controller
    {

        private readonly AppDbContext _context;
        private readonly UserManager<AppUser> _userManager;

        public OrderController(AppDbContext context, UserManager<AppUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }


        public IActionResult Checkout()
        {
            CheckoutViewModel vm = new CheckoutViewModel()
            {
                BasketViewModel = getBasket()
            };
            return View(vm);
        }

        [Authorize(Roles = "member")]
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Checkout(OrderCreateViewModel orderVM)
        {
            if (!ModelState.IsValid)
            {
                CheckoutViewModel vm = new CheckoutViewModel
                {
                    BasketViewModel = getBasket(),
                    Order = orderVM
                };
                return View(vm);
            }

            AppUser user = await _userManager.GetUserAsync(User);

            if (user == null) return RedirectToAction("login", "account");

            Order order = new Order
            {
                Address = orderVM.Address,
                Phone = orderVM.Phone,
                CreatedAt = DateTime.Now,
                AppUserId = user.Id,
                Email = user.Email,
                FullName = user.Fullname,
                Note = orderVM.Note,
                Status = Models.Enums.OrderStatus.Pending
            };

            var basketItems = _context.BasketItems.Include(x => x.Book).Where(x => x.AppUserId == user.Id).ToList();

            order.OrderItems = basketItems.Select(x => new OrderItem
            {
                BookId = x.BookId,
                Count = x.Count,
                SalePrice = (decimal)x.Book.SalePrice,
                DiscountPercent = (decimal)x.Book.DiscountPercent,
                CostPrice = (decimal)x.Book.CostPrice,
            }).ToList();

            _context.Orders.Add(order);
            _context.BasketItems.RemoveRange(basketItems);

            _context.SaveChanges();

            return RedirectToAction("profile", "account", new { tab = "orders" });
        }

        [Authorize(Roles ="member")]
        public IActionResult GetOrderItems(int orderId)
        {
            AppUser user = _userManager.GetUserAsync(User).Result;

         
            Order order = _context.Orders.Include(x=>x.OrderItems).ThenInclude(oi=>oi.Book).FirstOrDefault(x=>x.AppUserId==user.Id &&x.Id == orderId);
            if (order == null) return RedirectToAction("notfound", "error");

            return PartialView("_OrderDetailPartial", order.OrderItems);
        }

        [Authorize(Roles = "member")]
        public IActionResult Cancel(int id)
        {
            AppUser user = _userManager.GetUserAsync(User).Result;

            Order order = _context.Orders.FirstOrDefault(x => x.Id == id && x.AppUserId == user.Id && x.Status == Models.Enums.OrderStatus.Pending);

            if (order == null) return RedirectToAction("notfound", "error");

            order.Status = Models.Enums.OrderStatus.Canceled;
            _context.SaveChanges();
            return RedirectToAction("profile", "account", new { tab = "orders" });
        }

        private BasketViewModel getBasket()
        {
            BasketViewModel vm = new BasketViewModel
            {
                Items = new List<BasketItemViewModel>()
            };

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
                var cookieBasket = Request.Cookies["basket"];

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
