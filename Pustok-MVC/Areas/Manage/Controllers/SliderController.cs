using Humanizer.Localisation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Data;
using Pustok_MVC.Helpers;
using Pustok_MVC.Models;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Authorize(Roles = "admin,super_admin")]
    [Area("Manage")]
    public class SliderController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public SliderController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Sliders.OrderByDescending(x => x.Id);
            var data = PaginatedList<Slider>.Create(query,page,2);
            if (data.TotalPages < page) return RedirectToAction("index", new {page = data.TotalPages});
            return View(data);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Slider slider)
        {
            if (!ModelState.IsValid)
            {
                return View(slider);
            }

            if (slider.ImageFile.Length>2*1024*1024)
            {
                ModelState.AddModelError("ImageFile", "File must be less or equals than 2MB");
                return View();
            }
            /*if (slider.ImageFile.ContentType!="image/png" && slider.ImageFile.ContentType != "image/jpeg")
            {
                ModelState.AddModelError("ImageFile", "File type must be png, jpeg or jpg!");
                return View();
            }*/
            if (slider.ImageFile == null)
            {
                ModelState.AddModelError("ImageFile", "Please select a file.");
                return View();
            }


            slider.Image = FileManager.Save(slider.ImageFile, _env.WebRootPath, "manage/uploads/sliders");


            _context.Sliders.Add(slider);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Edit(int id)
        {
            Slider slider = _context.Sliders.Find(id);

            if (slider == null)
            {
                return View("error");
            }
            return View(slider);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(Slider slider)
        {
            if (!ModelState.IsValid) return View(slider);

            Slider existSlider = _context.Sliders.Find(slider.Id);
            if (existSlider == null) return RedirectToAction("Error", "NotFound");

            string deletedFile = null;
            if (slider.ImageFile != null)
            {
                if (slider.ImageFile.Length > 2 * 1024 * 1024)
                {
                    ModelState.AddModelError("ImageFile", "File must be less or equal than 2MB");
                    return View();
                }

               /* if (slider.ImageFile.ContentType != "image/png" && slider.ImageFile.ContentType != "image/jpeg")
                {
                    ModelState.AddModelError("ImageFile", "File type must be png,jpeg or jpg");
                    return View();
                }*/

                deletedFile = existSlider.Image;
                existSlider.Image = FileManager.Save(slider.ImageFile, _env.WebRootPath, "manage/uploads/sliders");

            }


            existSlider.Title1 = slider.Title1;
            existSlider.Title2 = slider.Title2;
            existSlider.Desc = slider.Desc;
            existSlider.Order = slider.Order;
            existSlider.BtnUrl = slider.BtnUrl;
            existSlider.BtnText = slider.BtnText;

            if (deletedFile != null)
            {
                FileManager.Delete(_env.WebRootPath, "manage/uploads/slider", deletedFile);
            }

            _context.SaveChanges();

            return RedirectToAction("Index");
        }


        public IActionResult Delete(int id)
        {
            Slider existSlider = _context.Sliders.Find(id);
            if (existSlider == null) return NotFound();

            _context.Sliders.Remove(existSlider);
            _context.SaveChanges();

            FileManager.Delete(_env.WebRootPath, "manage/uploads/slider", existSlider.Image);
            return Ok();
        }

    }
}
