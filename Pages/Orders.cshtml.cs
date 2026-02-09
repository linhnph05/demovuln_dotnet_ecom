using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using WebApp1.Models;

namespace WebApp1.Pages;

public class OrdersModel : PageModel
{
    private readonly string _connectionString;

    public OrdersModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

    public List<Order> Orders { get; set; } = new();

    public IActionResult OnGet()
    {
        var username = HttpContext.Session.GetString("Username");
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Login");
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var getUserQuery = $"SELECT Id FROM Users WHERE Username = '{username}'";
        using var getUserCommand = new SqliteCommand(getUserQuery, connection);
        var userId = Convert.ToInt32(getUserCommand.ExecuteScalar());

        var ordersQuery = $"SELECT * FROM Orders WHERE UserId = {userId} ORDER BY OrderDate DESC";
        using var ordersCommand = new SqliteCommand(ordersQuery, connection);
        using var reader = ordersCommand.ExecuteReader();

        while (reader.Read())
        {
            Orders.Add(new Order
            {
                Id = reader.GetInt32(0),
                UserId = reader.GetInt32(1),
                OrderDate = reader.GetDateTime(2),
                TotalAmount = reader.GetDecimal(3),
                Status = reader.GetString(4),
                ShippingAddress = reader.GetString(5)
            });
        }

        return Page();
    }
}
