using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NuGet.Protocol.Plugins;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Data;
using Pustok_MVC.Helpers;
using Pustok_MVC.Models;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Authorize(Roles = "admin,super_admin")]
    [Area("manage")]
    public class AuthorController : Controller
    {
        private readonly AppDbContext _context;

        public AuthorController(AppDbContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page = 1)
        {
            return View(PaginatedList<Author>.Create(_context.Authors.Include(x=>x.Books), page, 2));
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Author author)
        {
            if (ModelState.IsValid)
            {
                return View(author);
            }

            if (_context.Authors.Any(x => x.Fullname == author.Fullname))
            {
                ModelState.AddModelError("Fullname", "Author already exists!");
                return View(author);
            }

            _context.Authors.Add(author);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Edit(int id)
        {
            Author author = _context.Authors.Find(id);
            if (author == null)
            {
                return View("error");
            }

            return View(author);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(Author author)
        {

            if (!ModelState.IsValid)
            {
                return View();
            }
            Author existAuthor = _context.Authors.Find(author.Id);
            if (author == null)
            {
                return View("error");
            }
            existAuthor.Fullname = author.Fullname;
            _context.SaveChanges();

            return RedirectToAction("Index");
        }


        public IActionResult Delete(int id)
        {
            Author existAuthor = _context.Authors.Find(id);
            if (existAuthor == null) return NotFound();

            _context.Authors.Remove(existAuthor);
            _context.SaveChanges();

            return Ok();
        }
    }

    
}
