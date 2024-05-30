using Pustok_MVC.Models;

namespace Pustok_MVC.Areas.Manage.ViewModels
{
    public class PaginatedList<T>
    {
        public PaginatedList(List<T> items, int totalPages, int pageIndex, int pageSize)
        {
            this.Items = items;
            this.TotalPages = totalPages;
            this.PageIndex = pageIndex;
            PageSize = pageSize;

        }
        public List<T> Items { get; set; }
        public int PageIndex { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
        public bool HasPrevious => PageIndex > 1;
        public bool HasNext => PageIndex < TotalPages;

        public static PaginatedList<T> Create(IQueryable<T> query, int pageIndex, int pageSize)
        {
            int totalPages = (int)Math.Ceiling(query.Count() / 2d);
            var items = query.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList();

            return new PaginatedList<T>(items, totalPages, pageIndex, pageSize);
        }
    }
}
