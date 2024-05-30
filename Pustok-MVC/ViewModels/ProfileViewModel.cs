using Pustok_MVC.Models;

namespace Pustok_MVC.ViewModels
{
    public class ProfileViewModel
    {
        public ProfileEditViewModel ProfileEditVM { get; set; }
        public List<Order> Orders { get; set; }
    }
}
