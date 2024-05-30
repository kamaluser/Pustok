using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.Attributes
{
    public class CheckImageContentAttribute:ValidationAttribute
    {
        private readonly string[] _types;

        public CheckImageContentAttribute(params string[] types)
        {
            _types = types;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            List<IFormFile> list = new List<IFormFile>();
            if (value is IFormFile file)
            {
                list.Add(file);
            }
            else if (value is List<IFormFile> files)
            {
                list.AddRange(files);


            }
            foreach (var item in list)
            {
                if (!_types.Contains(item.ContentType))
                {
                    return new ValidationResult($"File content types must be {string.Join(",", _types)} ");

                }
            }
            return ValidationResult.Success;
        }
    }
}
