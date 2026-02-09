using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApp1.Pages;

public class CheckoutModel : PageModel
{
    [BindProperty]
    public string? ShippingAddress { get; set; }

    [BindProperty]
    public string? CardNumber { get; set; }

    public string? Message { get; set; }

    public void OnGet()
    {
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrEmpty(ShippingAddress))
        {
            Message = "Shipping address is required.";
            return Page();
        }

        Message = "Order placed successfully!";
        Response.Cookies.Delete("ShoppingCart");
        
        return Page();
    }
}
