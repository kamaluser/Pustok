using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Data;
using Pustok_MVC.Helpers;
using Pustok_MVC.Models;
using Pustok_MVC.Models.Enums;
using Pustok_MVC.ViewModels;
using static System.Reflection.Metadata.BlobBuilder;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Authorize(Roles = "admin,super_admin")]
    [Area("manage")]
    public class BookController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public BookController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Books.Include(x => x.Author).Include(x => x.Genre).Include(x => x.BookImages.Where(x => x.PosterStatus == true)).Where(x=>!x.IsDeleted).OrderByDescending(x => x.Id);

            var data = PaginatedList<Book>.Create(query, page, 2);
            if (data.TotalPages < page) return RedirectToAction("index", new { page = data.TotalPages });
            return View(data);
        }

        public IActionResult Create()
        {
            ViewBag.Authors = _context.Authors.ToList();
            ViewBag.Genres = _context.Genres.ToList();
            ViewBag.Tags = _context.Tags.ToList();

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Book book)
        {
            if (book.PosterFile == null) ModelState.AddModelError("PosterFile", "PosterFile is Required!");

            if (!ModelState.IsValid)
            {
                ViewBag.Authors = _context.Authors.ToList();
                ViewBag.Genres = _context.Genres.ToList();
                ViewBag.Tags = _context.Tags.ToList();

                return View(book);
            }

            if (!_context.Authors.Any(x => x.Id == book.AuthorId))
                return RedirectToAction("NotFound", "Error");

            if (!_context.Genres.Any(x => x.Id == book.GenreId))
                return RedirectToAction("NotFound", "Error");

            BookImage poster = new BookImage
            {
                PosterStatus = true,
                Name = FileManager.Save(book.PosterFile, _env.WebRootPath, "manage/uploads/books"),

            };

            book.BookImages.Add(poster);
            _context.BookImages.Add(poster);
            BookImage hoverPoster = new BookImage
            {
                PosterStatus = false,
                Name = FileManager.Save(book.HoverPosterFile, _env.WebRootPath, "manage/uploads/books"),

            };
            book.BookImages.Add(hoverPoster);

            foreach (var imgFile in book.ImageFiles)
            {
                BookImage bookImg = new BookImage
                {
                    Name = FileManager.Save(imgFile, _env.WebRootPath, "manage/uploads/books"),
                    PosterStatus = null,
                };
                book.BookImages.Add(bookImg);
            }


            _context.Books.Add(book);
            _context.SaveChanges();

            return RedirectToAction("Index");
        }

        /*[HttpPost]
        public IActionResult Edit(Book book)
        {
            Book existBook = _context.Books
                .Include(b => b.BookImages)
                .FirstOrDefault(b => b.Id == book.Id);

            if (existBook == null)
                return RedirectToAction("NotFound", "Error");

            if (book.AuthorId != existBook.AuthorId && !_context.Authors.Any(x => x.Id == book.AuthorId))
                return RedirectToAction("NotFound", "Error");

            if (book.GenreId != existBook.GenreId && !_context.Genres.Any(x => x.Id == book.GenreId))
                return RedirectToAction("NotFound", "Error");

            existBook.Name = book.Name;
            existBook.Desc = book.Desc;
            existBook.SalePrice = book.SalePrice;
            existBook.CostPrice = book.CostPrice;
            existBook.DiscountPercent = book.DiscountPercent;
            existBook.IsNew = book.IsNew;
            existBook.IsFeatured = book.IsFeatured;
            existBook.StockStatus = book.StockStatus;


            if (book.PosterFile != null)
            {
                FileManager.Delete(_env.WebRootPath, "manage/uploads/books", existBook.BookImages.FirstOrDefault(x => x.PosterStatus == true)?.Name);

                BookImage poster = new BookImage
                {
                    PosterStatus = true,
                    Name = FileManager.Save(book.PosterFile, _env.WebRootPath, "manage/uploads/books")
                };
                existBook.BookImages.Add(poster);
            }

            if (book.HoverPosterFile != null)
            {
                FileManager.Delete(_env.WebRootPath, "manage/uploads/books", existBook.BookImages.FirstOrDefault(x => x.PosterStatus == false)?.Name);

                BookImage hoverPoster = new BookImage
                {
                    PosterStatus = false,
                    Name = FileManager.Save(book.HoverPosterFile, _env.WebRootPath, "manage/uploads/books")
                };
                existBook.BookImages.Add(hoverPoster);
            }

            if (book.ImageFiles != null && book.ImageFiles.Any())
            {
                FileManager.DeleteAll(_env.WebRootPath, "manage/uploads/books", existBook.BookImages.Where(x => x.PosterStatus == null).Select(x => x.Name).ToList());

                foreach (var imgFile in book.ImageFiles)
                {
                    BookImage bookImg = new BookImage
                    {
                        Name = FileManager.Save(imgFile, _env.WebRootPath, "manage/uploads/books"),
                        PosterStatus = null,
                    };
                    existBook.BookImages.Add(bookImg);
                }
            }

            existBook.ModifiedAt = DateTime.UtcNow;

            _context.SaveChanges();

            return RedirectToAction("index");
        }*/


        public IActionResult Edit(int id)
        {


            Book books = _context.Books.Include(x => x.BookImages).Include(x => x.BookTags).FirstOrDefault(x => x.Id == id);



            if (books == null)
            {
                return View("error");
            }

            books.TagIds = books.BookTags.Select(x => x.TagId).ToList();


            ViewBag.Authors = _context.Authors.ToList();
            ViewBag.Genres = _context.Genres.ToList();
            ViewBag.Tags = _context.Tags.ToList();
            return View(books);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(Book book)
        {

            Book existsbook = _context.Books.Include(x => x.BookImages).Include(x => x.BookTags).FirstOrDefault(x => x.Id == book.Id);

            if (existsbook == null)
            {
                return View("Error");
            }

            if (existsbook.BookImages == null)
            {
                return RedirectToAction("notfound", "error");
            }


            if (!_context.Authors.Any(x => x.Id == book.AuthorId))
            {
                return View("Error");
            }



            if (!_context.Genres.Any(x => x.Id == book.GenreId))
            {
                return View("Error");
            }

            /*existsbook.BookTags = new List<BookTag>();

            foreach (var tagId in book.TagIds)
            {
                if (!_context.Tags.Any(x => x.Id == tagId))
                {
                    return View("Error");
                }

                existsbook.BookTags.Add(new BookTag() { TagId = tagId });

            }*/


            existsbook.BookTags.RemoveAll(x => !book.TagIds.Contains(x.TagId));



            foreach (var tagId in book.TagIds.FindAll(x => !existsbook.BookTags.Any(bt => bt.TagId == x)))
            {
                if (!_context.Tags.Any(x => x.Id == tagId)) return RedirectToAction("notfound", "error");

                BookTag bookTag = new BookTag
                {
                    TagId = tagId,
                };
                existsbook.BookTags.Add(bookTag);
            }


            List<string> removedFileNames = new List<string>();


            List<BookImage> removedImages = existsbook.BookImages.FindAll(x => x.PosterStatus == null && !book.BookImageIds.Contains(x.Id));
            removedFileNames = removedImages.Select(x => x.Name).ToList();

            _context.BookImages.RemoveRange(removedImages);

            List<string> removeableFile = new List<string>();
            if (book.PosterFile != null)
            {
                BookImage poster = existsbook.BookImages.FirstOrDefault(x => x.PosterStatus == true);
                if (poster != null)
                {
                    removeableFile.Add(poster.Name);
                    poster.Name = FileManager.Save(book.PosterFile, _env.WebRootPath, "manage/uploads/books");
                }
            }
            if (book.HoverPosterFile != null)
            {
                BookImage hoverPoster = existsbook.BookImages.FirstOrDefault(x => x.PosterStatus == false);

                if (hoverPoster != null)
                {
                    removeableFile.Add(hoverPoster.Name);
                    hoverPoster.Name = FileManager.Save(book.HoverPosterFile, _env.WebRootPath, "manage/uploads/books");
                }
            }

            foreach (var file in book.ImageFiles)
            {
                BookImage image = new BookImage()
                {

                    PosterStatus = null,
                    Name = FileManager.Save(file, _env.WebRootPath, "manage/uploads/books")

                };
                existsbook.BookImages.Add(image);
            }

            existsbook.Name = book.Name;
            existsbook.Desc = book.Desc;
            existsbook.CostPrice = book.CostPrice;
            existsbook.SalePrice = book.SalePrice;
            existsbook.DiscountPercent = book.DiscountPercent;
            existsbook.IsFeatured = book.IsFeatured;
            existsbook.IsNew = book.IsNew;
            existsbook.StockStatus = book.StockStatus;
            existsbook.AuthorId = book.AuthorId;
            existsbook.GenreId = book.GenreId;
            existsbook.ModifiedAt = DateTime.UtcNow;


            _context.SaveChanges();

            if (removeableFile.Count > 0)
            {
                FileManager.DeleteAll(_env.WebRootPath, "manage/uploads/books", removeableFile);
            }


            if(removedFileNames.Count>0)
            {
                FileManager.DeleteAll(_env.WebRootPath, "manage/uploads/books", removedFileNames);
            }

            return RedirectToAction("Index");
        }
        public IActionResult Delete(int id)
        {
            Book book = _context.Books.Include(x=>x.BookImages)
                .Include(x=>x.Author)
                .Include(x=>x.Genre)
                .Include(x=>x.BookTags).ThenInclude(bt=>bt.Tag).FirstOrDefault(x=>x.Id == id && !x.IsDeleted);

            if (book == null) return RedirectToAction("notfound", "error");

            return View(book);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Delete(Book book)
        {
            Book existsBook = _context.Books.FirstOrDefault(x => x.Id == book.Id && !x.IsDeleted);
            if (existsBook == null) return RedirectToAction("notfound", "error");

            existsBook.IsDeleted = true;
            existsBook.ModifiedAt = DateTime.UtcNow;
            _context.SaveChanges();

            return RedirectToAction("index");
        }


        /*public async Task<IActionResult> AddToBasket(int bookId)
        {
            var book = await _context.Books.FindAsync(bookId);

            if (book == null)
            {
                return NotFound();
            }

            List<BasketViewModel> basketVMList = new List<BasketViewModel>();
            BasketViewModel basketVM = null;
            AppUser appUser = null;
            var basketVMstr = HttpContext.Request.Cookies["basketVMList"];

            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                if (basketVMstr != null)
                {
                    basketVMList = JsonConvert.DeserializeObject<List<BasketViewModel>>(basketVMstr);

                    var basketViewM = basketVMList.FirstOrDefault(bvm => bvm.BookId == bookId);

                    if (basketViewM != null)
                    {
                        basketViewM.Count++;

                    }
                    else
                    {
                        basketVM = new BasketViewModel
                        {
                            BookId = bookId,
                            Title = book.Name,
                            Price = (book.SalePrice * (100 - book.DiscountPercent)) / 100,
                            Count = 1,
                            ImageUrl = book.BookImages.FirstOrDefault(x => x.PosterStatus == true)?.Name
                        };
                        basketVMList.Add(basketVM);
                    }
                }
                else
                {
                    basketVM = new BasketViewModel
                    {
                        BookId = bookId,
                        Count = 1
                    };
                    basketVMList.Add(basketVM);
                }

                var BasketVMstr = JsonConvert.SerializeObject(basketVMList);

                HttpContext.Response.Cookies.Append("basketVMList", BasketVMstr);
            }
            else
            {
                string Username = HttpContext.User.Identity.Name;
                appUser = await _userManager.FindByNameAsync(Username);
                var basketItem = await _context.BasketItems.FirstOrDefaultAsync(bi => bi.AppUserId == appUser.Id && bi.BookId == bookId);
                if (basketItem != null)
                {
                    basketItem.Count++;
                }
                else
                {
                    BasketItem BasketItem = new BasketItem
                    {
                        AppUserId = appUser.Id,
                        BookId = bookId,
                        Count = 1,
                    };
                    _context.BasketItems.Add(BasketItem);
                }
            }
            _context.SaveChanges();

            *//*return Ok();*//*

            return RedirectToAction("index", "home");
        }

        public IActionResult GetBasket()
        {
            List<BasketViewModel> basketVMList = new List<BasketViewModel>();

            var BasketVMstr = HttpContext.Request.Cookies["BasketVMList"];
            if (BasketVMstr != null)
            {
                basketVMList = JsonConvert.DeserializeObject<List<BasketViewModel>>(BasketVMstr);
            }

            return RedirectToAction("index", "basket");
        }*/


        public IActionResult BookReview(int id)
        {
            Book book = _context.Books.Include(c => c.BookReviews).ThenInclude(r => r.AppUser).FirstOrDefault(x => x.Id == id);

            return View(book);
        }

        public IActionResult AcceptReview(int reviewId)
        {
            var review = _context.BookReviews.FirstOrDefault(x => x.Id == reviewId);
            if (review != null)
            {
                review.Status = ReviewStatus.Accepted;
                _context.SaveChanges();
            }
            return RedirectToAction("BookReview", new { id = review.BookId });
        }

        public IActionResult RejectReview(int reviewId)
        {
            var review = _context.BookReviews.FirstOrDefault(x => x.Id == reviewId);
            if (review != null)
            {
                review.Status = ReviewStatus.Rejected;
                _context.SaveChanges();
            }
            return RedirectToAction("BookReview", new { id = review.BookId });
        }


    }
}