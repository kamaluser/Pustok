using System.ComponentModel.DataAnnotations;

namespace Pustok_MVC.Attributes
{
    public class MaxSizeAttribute : ValidationAttribute
    {
        private int _byteSize;
        public MaxSizeAttribute(int byteSize)
        {
            _byteSize = byteSize;
        }
        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {

            List<IFormFile> fileList = new List<IFormFile>();

            if (value is List<IFormFile> files) fileList = files;
            else if (value is IFormFile file) fileList.Add(file);


            foreach (var file in fileList)
            {
                if ((file != null))
                {
                    if (file.Length > _byteSize)
                    {
                        double mb = _byteSize / 1024d / 1024d;
                        return new ValidationResult($"File must be less or equal than {mb.ToString("0.##")}mb");
                    }
                }
            }


            return ValidationResult.Success;

        }
    }
}
