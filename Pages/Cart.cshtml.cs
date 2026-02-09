using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using System.Text.Json;
using WebApp1.Models;

namespace WebApp1.Pages;

public class CartModel : PageModel
{
    private readonly string _connectionString;

    public CartModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

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
                CartItems = JsonSerializer.Deserialize<List<CartItem>>(cartCookie) ?? new List<CartItem>();
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
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            var query = $"SELECT * FROM Products WHERE Id = {productId}";
            using var command = new SqliteCommand(query, connection);
            using var reader = command.ExecuteReader();
            
            if (reader.Read())
            {
                CartItems.Add(new CartItem
                {
                    ProductId = reader.GetInt32(0),
                    ProductName = reader.GetString(1),
                    Price = reader.GetDecimal(3),
                    Quantity = 1
                });
            }
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
        var json = JsonSerializer.Serialize(CartItems);
        Response.Cookies.Append("ShoppingCart", json, new CookieOptions
        {
            Expires = DateTimeOffset.Now.AddDays(7),
            HttpOnly = true
        });
    }
}

