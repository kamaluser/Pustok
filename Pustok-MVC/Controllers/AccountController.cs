using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MimeKit;
using MailKit;
using MailKit.Net.Smtp;
using Pustok_MVC.Data;
using Pustok_MVC.Models;
using Pustok_MVC.ViewModels;
using System.Net.Mail;
using System.Security.Claims;

namespace Pustok_MVC.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly AppDbContext _context;

        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, AppDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
        }
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(MemberRegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (_userManager.Users.Any(x => x.NormalizedEmail == model.Email.ToUpper()))
            {
                ModelState.AddModelError("Email", "Email is already taken");
                return View();
            }


            AppUser user = new AppUser
            {
                UserName = model.UserName,
                Email = model.Email,
                Fullname = model.FullName
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                {
                    if (err.Code == "DuplicateUserName")
                        ModelState.AddModelError("UserName", "UserName is already registered!");
                    else ModelState.AddModelError("", err.Description);
                }
                return View();
            }
            await _userManager.AddToRoleAsync(user, "member");

            return RedirectToAction("index", "home");
        }


        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(MemberLoginModel model, string? returnUrl)
        {
            if ((!ModelState.IsValid)) return View();

            AppUser? user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !await _userManager.IsInRoleAsync(user, "member"))
            {
                ModelState.AddModelError("", "Email or Password is incorrect!");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, true);

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "You are locked out for 5 minutes!");
                return View();
            }

            else if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Email or Password incorrect");
                return View();
            }

            return returnUrl != null ? Redirect(returnUrl) : RedirectToAction("index", "home");

        }

        [Authorize(Roles = "member")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [Authorize(Roles = "member")]
        public async Task<IActionResult> Profile(string tab = "dashboard")
        {
            AppUser? user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                return RedirectToAction("login", "account");
            }

            ProfileViewModel profileVM = new ProfileViewModel
            {
                ProfileEditVM = new ProfileEditViewModel
                {
                    FullName = user.Fullname,
                    Email = user.Email,
                    UserName = user.UserName
                },
                Orders = _context.Orders.Include(x => x.OrderItems).ThenInclude(oi => oi.Book).OrderByDescending(x => x.CreatedAt).Where(x => x.AppUserId == user.Id).ToList(),
            };

            ViewBag.Tab = tab;

            return View(profileVM);
        }

        [Authorize(Roles = "member")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Profile(ProfileEditViewModel editVM, string? tab = "profile")
        {
            ViewBag.Tab = tab;

            ProfileViewModel profileVM = new ProfileViewModel();
            profileVM.ProfileEditVM = editVM;

            if (!ModelState.IsValid) return View(editVM);

            AppUser? user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                return RedirectToAction("login", "account");
            }
            user.UserName = editVM.UserName;
            user.Email = editVM.Email;
            user.Fullname = editVM.FullName;

            if (_userManager.Users.Any(x => x.Id != User.FindFirstValue(ClaimTypes.NameIdentifier) && x.NormalizedEmail == editVM.Email.ToUpper()))
            {
                ModelState.AddModelError("Email", "Email is already taken!");
                return View(profileVM);
            }

            if (editVM.NewPassword != null)
            {
                var passwordResult = await _userManager.ChangePasswordAsync(user, editVM.CurrentPassword, editVM.NewPassword);

                if (!passwordResult.Succeeded)
                {
                    foreach (var err in passwordResult.Errors)
                        ModelState.AddModelError("", err.Description);

                    return View(profileVM);
                }
            }

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                {
                    if (err.Code == "DuplicateUserName")
                        ModelState.AddModelError("UserName", "UserName is already taken");
                    else ModelState.AddModelError("", err.Description);
                }
                return View(profileVM);
            }

            await _signInManager.SignInAsync(user, false);

            return View(profileVM);
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public IActionResult ForgetPassword(ForgetPasswordViewModel vm)
        {
            if (!ModelState.IsValid) return View(vm);
            AppUser? user = _userManager.FindByEmailAsync(vm.Email).Result;
            if (user == null || !_userManager.IsInRoleAsync(user, "member").Result)
            {
                ModelState.AddModelError("", "Account is not exist");
                return View();
            }
            var token = _userManager.GeneratePasswordResetTokenAsync(user).Result;
            var url = Url.Action("verify", "account", new { email = vm.Email, token = token }, Request.Scheme);
            TempData["EmailSent"] = vm.Email;

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Sending User", "domingo.collins75@ethereal.email"));
            message.To.Add(new MailboxAddress(user.UserName, user.Email));
            message.Subject = "Resetting Password";
            message.Body = new TextPart("You can reset password already.")
            {
                Text = $"Hi {user.UserName},\n\nPlease click link for reseting password:\n\n{url}"
            };

            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    client.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
                    client.Authenticate("domingo.collins75@ethereal.email", "2yCmZY63vwMYZWMz87");
                    client.Send(message);
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Email sending failed: {ex.Message}");
                    return View(vm);
                }
                finally
                {
                    client.Disconnect(true);
                }
            }

            return Json(new { url = url });
        }

        public IActionResult Verify(string email,string token)
        {
            AppUser? user = _userManager.FindByEmailAsync(email).Result;

            if (user == null || !_userManager.IsInRoleAsync(user, "member").Result)
            {
                return RedirectToAction("notfound", "error");
            }

            if (!_userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", token).Result)
            {
                return RedirectToAction("notfound", "error");
            }

            TempData["email"] = email;
            TempData["token"] = token;

            return RedirectToAction("resetPassword");
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public IActionResult ResetPassword(ResetPasswordViewModel vm)
        {
            AppUser? user = _userManager.FindByEmailAsync(vm.Email).Result;

            if (user == null || !_userManager.IsInRoleAsync(user, "member").Result)
            {
                ModelState.AddModelError("", "Account is not exist");
                return View();
            }

            if (!_userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", vm.Token).Result)
            {
                ModelState.AddModelError("", "Account is not exist");
                return View();
            }

            var result = _userManager.ResetPasswordAsync(user, vm.Token, vm.NewPassword).Result;

            if (!result.Succeeded)
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError("", item.Description);
                }
                return View();
            }

            //deyisildi

            return RedirectToAction("login");
        }
    }
}
