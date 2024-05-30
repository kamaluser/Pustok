using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Pustok_MVC.Areas.Manage.ViewModels;
using Pustok_MVC.Models;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    [Area("manage")]
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> CreateAdmin()
        {
            AppUser admin = new AppUser
            {
                UserName = "admin",
            };

            var result = await _userManager.CreateAsync(admin, "Admin123");
            await _userManager.AddToRoleAsync(admin, "super_admin");
            return Json(result);
        }

        public async Task<IActionResult> CreateRoles()
        {
            await _roleManager.CreateAsync(new IdentityRole("admin"));
            await _roleManager.CreateAsync(new IdentityRole("super_admin"));
            await _roleManager.CreateAsync(new IdentityRole("member"));

            return Ok();
        }
        public IActionResult Login()
        {
            return View();
        }

        /*[HttpPost]
        public async Task<IActionResult> Login(AdminLoginViewModel model)
        {
            AppUser admin = await _userManager.FindByNameAsync(model.UserName);

            if (admin == null)
            {
                ModelState.AddModelError("", "Username or password is incorrect!");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(admin, model.Password, false, false);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username or password is incorrect!");
                return View();
            }

            return RedirectToAction("index", "dashboard");
        }*/


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(AdminLoginViewModel model)
        {
            if (ModelState.IsValid) 
            {
                if (!string.IsNullOrEmpty(model.UserName) && !string.IsNullOrEmpty(model.Password))
                {
                    AppUser admin = await _userManager.FindByNameAsync(model.UserName);

                    if (admin != null)
                    {
                        var result = await _signInManager.PasswordSignInAsync(admin, model.Password, model.RememberMe, false);

                        if (result.Succeeded)
                        {
                            return RedirectToAction("index", "dashboard");
                        }
                    }
                }
            }

            ModelState.AddModelError("", "Username or password is incorrect!");
            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }
    }
}
