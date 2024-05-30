using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Pustok_MVC.Areas.Manage.Controllers
{
    public class DashboardController : Controller
    {
        [Authorize(Roles ="admin,super_admin")]
        [Area("manage")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
