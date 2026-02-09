using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using WebApp1.Models;

namespace WebApp1.Pages;

public class CartModel : PageModel
{
    public List<CartItem> CartItems { get; set; } = new();
    public decimal TotalAmount => CartItems.Sum(x => x.Price * x.Quantity);

    public void OnGet()
    {
        LoadCart();
    }

    private void LoadCart()
    {
        var cartCookie = Request.Cookies["ShoppingCart"];
        if (!string.IsNullOrEmpty(cartCookie))
        {
            try
            {
                byte[] data = Convert.FromBase64String(cartCookie);
                using var ms = new MemoryStream(data);
                
#pragma warning disable SYSLIB0011
                var formatter = new BinaryFormatter();
                CartItems = (List<CartItem>)formatter.Deserialize(ms);
#pragma warning restore SYSLIB0011
            }
            catch
            {
                CartItems = new List<CartItem>();
            }
        }
    }

    public IActionResult OnGetAdd(int productId)
    {
        LoadCart();
        
        var existingItem = CartItems.FirstOrDefault(x => x.ProductId == productId);
        if (existingItem != null)
        {
            existingItem.Quantity++;
        }
        else
        {
            CartItems.Add(new CartItem
            {
                ProductId = productId,
                ProductName = $"Product {productId}",
                Price = 99.99m,
                Quantity = 1
            });
        }

        SaveCart();
        return RedirectToPage("/Cart");
    }

    public IActionResult OnGetRemove(int productId)
    {
        LoadCart();
        var item = CartItems.FirstOrDefault(x => x.ProductId == productId);
        if (item != null)
        {
            CartItems.Remove(item);
        }
        SaveCart();
        return RedirectToPage("/Cart");
    }

    private void SaveCart()
    {
        using var ms = new MemoryStream();
#pragma warning disable SYSLIB0011
        var formatter = new BinaryFormatter();
        formatter.Serialize(ms, CartItems);
#pragma warning restore SYSLIB0011
        
        var data = Convert.ToBase64String(ms.ToArray());
        Response.Cookies.Append("ShoppingCart", data, new CookieOptions
        {
            Expires = DateTimeOffset.Now.AddDays(7)
        });
    }
}
