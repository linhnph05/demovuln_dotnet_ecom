using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Xml;
using WebApp1.Models;

namespace WebApp1.Pages;

public class ImportProductsModel : PageModel
{
    [BindProperty]
    public string? XmlData { get; set; }

    public List<Product> ImportedProducts { get; set; } = new();
    public string? ErrorMessage { get; set; }

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

        if (!string.IsNullOrEmpty(XmlData))
        {
            try
            {
                var xmlDoc = new XmlDocument();
                
                xmlDoc.XmlResolver = new XmlUrlResolver();
                xmlDoc.LoadXml(XmlData);

                var productNodes = xmlDoc.SelectNodes("//Product");
                
                if (productNodes != null)
                {
                    foreach (XmlNode node in productNodes)
                    {
                        var product = new Product
                        {
                            Name = node.SelectSingleNode("Name")?.InnerText ?? "",
                            Description = node.SelectSingleNode("Description")?.InnerText ?? "",
                            Price = decimal.Parse(node.SelectSingleNode("Price")?.InnerText ?? "0"),
                            Stock = int.Parse(node.SelectSingleNode("Stock")?.InnerText ?? "0"),
                            Category = node.SelectSingleNode("Category")?.InnerText ?? ""
                        };
                        ImportedProducts.Add(product);
                    }
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error parsing XML: {ex.Message}";
            }
        }

        return Page();
    }
}
