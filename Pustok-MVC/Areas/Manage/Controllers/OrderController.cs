using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Data;
using Pustok_MVC.Models;
using Pustok_MVC.Models.Enums;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Area("manage")]
    public class OrderController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public OrderController(AppDbContext context,IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Orders.Include(x => x.OrderItems).OrderByDescending(x => x.Id);
            var data = PaginatedList<Order>.Create(query, page, 2);
            if (data.TotalPages < page) return RedirectToAction("index", new { page = data.TotalPages });
            return View(data);
        }

        public IActionResult Detail(int id)
        {
            Order order = _context.Orders.Include(x=>x.OrderItems).ThenInclude(x=>x.Book).ThenInclude(x=>x.Author).FirstOrDefault(x=>x.Id == id);
            if (order == null) return View("index");
            return View(order);
        }

        public IActionResult ChangeStatus(int id, OrderStatus status)
        {
            Order order = _context.Orders.Include(x=>x.OrderItems).FirstOrDefault(y=>y.Id == id);
            if (order == null) return RedirectToAction("notfound", "error");

            order.Status = status;
            _context.SaveChanges();

            return RedirectToAction("Index", "Order");
        }
    }
}
