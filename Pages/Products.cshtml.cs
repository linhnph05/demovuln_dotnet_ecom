using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using WebApp1.Models;

namespace WebApp1.Pages;

public class ProductsModel : PageModel
{
    private readonly string _connectionString;

    public ProductsModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

    public List<Product> Products { get; set; } = new();
    
    [BindProperty(SupportsGet = true)]
    public string? SearchTerm { get; set; }

    public void OnGet()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        string query;
        if (!string.IsNullOrEmpty(SearchTerm))
        {
            query = $"SELECT * FROM Products WHERE Name LIKE '%{SearchTerm}%' OR Category LIKE '%{SearchTerm}%'";
        }
        else
        {
            query = "SELECT * FROM Products";
        }

        using var command = new SqliteCommand(query, connection);
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            Products.Add(new Product
            {
                Id = reader.GetInt32(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2),
                Price = reader.GetDecimal(3),
                Stock = reader.GetInt32(4),
                Category = reader.GetString(5),
                ImageUrl = reader.GetString(6)
            });
        }
    }
}
