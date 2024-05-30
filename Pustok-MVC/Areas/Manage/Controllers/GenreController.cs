using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Data;
using Pustok_MVC.Models;


namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Authorize(Roles = "admin,super_admin")]
    [Area("manage")]
    public class GenreController : Controller
    {
        private readonly AppDbContext _context;

        public GenreController(AppDbContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Genres.Include(x => x.Books);
            return View(PaginatedList<Genre>.Create(query, page, 2));
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Genre genre)
        {
            if (!ModelState.IsValid)
            {
                return View(genre);
            }

            if (_context.Genres.Any(x => x.Name == genre.Name))
            {
                ModelState.AddModelError("Name", "Genre already exists!");
                return View(genre);
            }

            _context.Genres.Add(genre);
            _context.SaveChanges();

            return RedirectToAction("Index");
        }


        public IActionResult Edit(int id)
        {
            Genre genre = _context.Genres.Find(id);
            if (genre == null) return RedirectToAction("Error", "NotFound");
            return View(genre);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(Genre genre)
        {
            if (!ModelState.IsValid)
            {
                return View(genre);
            }

            Genre existGenre = _context.Genres.Find(genre.Id);

            if (existGenre == null) return RedirectToAction("Error", "NotFound");

            if (_context.Genres.Any(x => x.Name == genre.Name))
            {
                ModelState.AddModelError("Name", "Genre already exists!");
                return View(genre);
            }

            existGenre.Name = genre.Name;
            _context.SaveChanges();

            return RedirectToAction("Index");
        }

        public IActionResult Delete(int id)
        {
            Genre genre = _context.Genres.Find(id);
            if (genre == null) return StatusCode(404);

            _context.Genres.Remove(genre);
            _context.SaveChanges();


            return RedirectToAction("index");
        }
    }
}
