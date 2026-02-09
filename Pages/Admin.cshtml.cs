using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using RazorEngine;
using RazorEngine.Templating;

namespace WebApp1.Pages;

public class AdminModel : PageModel
{
    [BindProperty]
    public string? EmailTemplate { get; set; }

    [BindProperty]
    public string? CustomerName { get; set; }

    [BindProperty]
    public string? OrderId { get; set; }

    public string? RenderedEmail { get; set; }

    public IActionResult OnGet()
    {
        var username = HttpContext.Session.GetString("Username");
        var isAdmin = HttpContext.Session.GetString("IsAdmin");

        if (string.IsNullOrEmpty(username) || isAdmin != "True")
        {
            return RedirectToPage("/Login");
        }

        return Page();
    }

    public IActionResult OnPost()
    {
        var username = HttpContext.Session.GetString("Username");
        var isAdmin = HttpContext.Session.GetString("IsAdmin");

        if (string.IsNullOrEmpty(username) || isAdmin != "True")
        {
            return RedirectToPage("/Login");
        }

        if (!string.IsNullOrEmpty(EmailTemplate))
        {
            try
            {
                var model = new
                {
                    CustomerName = CustomerName ?? "Customer",
                    OrderId = OrderId ?? "N/A",
                    Date = DateTime.Now.ToString()
                };

                RenderedEmail = Engine.Razor.RunCompile(EmailTemplate, "emailTemplate", null, model);
            }
            catch (Exception ex)
            {
                RenderedEmail = $"Error rendering template: {ex.Message}";
            }
        }

        return Page();
    }
}
