using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Controllers;

public class HomeController : Controller
{
    private readonly DbHelper _db;

    public HomeController(DbHelper db) => _db = db;

    public async Task<IActionResult> Index(string? category)
    {
        // VULNERABLE: SQL Injection via category parameter — no parameterisation
        var sql = string.IsNullOrEmpty(category)
            ? "SELECT * FROM Products ORDER BY CreatedAt DESC LIMIT 12"
            : $"SELECT * FROM Products WHERE Category = '{category}' ORDER BY CreatedAt DESC";

        var rows = await _db.ExecuteQueryAsync(sql);
        var catRows = await _db.ExecuteQueryAsync("SELECT DISTINCT Category FROM Products ORDER BY Category");

        var products = rows.Select(MapProduct).ToList();
        var categories = catRows.Select(r => r["Category"]?.ToString() ?? "").ToList();

        ViewBag.Categories = categories;
        ViewBag.CurrentCategory = category;
        return View(products);
    }

    // VULNERABLE: SQL Injection via q parameter
    public async Task<IActionResult> Search(string q = "")
    {
        var sql = $"SELECT * FROM Products WHERE Name LIKE '%{q}%' OR Description LIKE '%{q}%' OR Category LIKE '%{q}%'";
        var rows = await _db.ExecuteQueryAsync(sql);
        ViewBag.Query = q;
        return View(rows.Select(MapProduct).ToList());
    }

    public IActionResult Privacy() => View();

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() =>
        View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });

    internal static Product MapProduct(Dictionary<string, object?> r) => new()
    {
        Id = Convert.ToInt32(r["Id"]),
        Name = r["Name"]?.ToString() ?? "",
        Description = r["Description"]?.ToString() ?? "",
        Price = Convert.ToDecimal(r["Price"]),
        Stock = Convert.ToInt32(r["Stock"]),
        Category = r["Category"]?.ToString() ?? "",
        ImageUrl = r["ImageUrl"]?.ToString() ?? "",
        CreatedAt = r.ContainsKey("CreatedAt") && r["CreatedAt"] != null
            ? Convert.ToDateTime(r["CreatedAt"]) : DateTime.UtcNow
    };
}
