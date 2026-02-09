using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using WebApp1.Models;

namespace WebApp1.Pages;

public class CheckoutModel : PageModel
{
    private readonly string _connectionString;

    public CheckoutModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

    [BindProperty]
    public string? ShippingAddress { get; set; }

    [BindProperty]
    public string? CardNumber { get; set; }

    public string? Message { get; set; }
    public List<CartItem> CartItems { get; set; } = new();
    public decimal TotalAmount => CartItems.Sum(x => x.Price * x.Quantity);

    public IActionResult OnGet()
    {
        var username = HttpContext.Session.GetString("Username");
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Login");
        }

        LoadCart();
        
        if (!CartItems.Any())
        {
            return RedirectToPage("/Cart");
        }

        return Page();
    }

    public IActionResult OnPost()
    {
        var username = HttpContext.Session.GetString("Username");
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Login");
        }

        LoadCart();

        if (string.IsNullOrEmpty(ShippingAddress))
        {
            Message = "Shipping address is required.";
            return Page();
        }

        if (!CartItems.Any())
        {
            Message = "Your cart is empty.";
            return Page();
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var getUserQuery = $"SELECT Id FROM Users WHERE Username = '{username}'";
        using var getUserCommand = new SqliteCommand(getUserQuery, connection);
        var userId = Convert.ToInt32(getUserCommand.ExecuteScalar());

        var orderQuery = $"INSERT INTO Orders (UserId, OrderDate, TotalAmount, Status, ShippingAddress) VALUES ({userId}, '{DateTime.Now:yyyy-MM-dd HH:mm:ss}', {TotalAmount}, 'Pending', '{ShippingAddress}'); SELECT last_insert_rowid();";
        using var orderCommand = new SqliteCommand(orderQuery, connection);
        var orderId = Convert.ToInt32(orderCommand.ExecuteScalar());

        foreach (var item in CartItems)
        {
            var itemQuery = $"INSERT INTO OrderItems (OrderId, ProductId, Quantity, Price) VALUES ({orderId}, {item.ProductId}, {item.Quantity}, {item.Price})";
            using var itemCommand = new SqliteCommand(itemQuery, connection);
            itemCommand.ExecuteNonQuery();

            var updateStockQuery = $"UPDATE Products SET Stock = Stock - {item.Quantity} WHERE Id = {item.ProductId}";
            using var updateCommand = new SqliteCommand(updateStockQuery, connection);
            updateCommand.ExecuteNonQuery();
        }

        Message = $"Order #{orderId} placed successfully! Total: ${TotalAmount:F2}";
        Response.Cookies.Delete("ShoppingCart");
        CartItems.Clear();
        
        return Page();
    }

    private void LoadCart()
    {
        var cartCookie = Request.Cookies["ShoppingCart"];
        if (!string.IsNullOrEmpty(cartCookie))
        {
            try
            {
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All
                };
                CartItems = JsonConvert.DeserializeObject<List<CartItem>>(cartCookie, settings) ?? new List<CartItem>();
            }
            catch
            {
                CartItems = new List<CartItem>();
            }
        }
    }
}

