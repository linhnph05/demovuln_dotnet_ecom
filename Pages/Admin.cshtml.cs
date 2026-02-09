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

    public void OnGet()
    {
    }

    public void OnPost()
    {
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
    }
}
