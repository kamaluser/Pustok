using Microsoft.AspNetCore.Identity;

namespace Pustok_MVC.Models
{
    public class AppUser:IdentityUser
    {
        public string Fullname { get; set; }
    }
}
