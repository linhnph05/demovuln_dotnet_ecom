using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApp1.Pages
{
    public class IndexModel : PageModel
    {
        public string Message { get; set; } = "Hello, C# Web App!";
        public void OnGet()
        {

        }
    }
}
