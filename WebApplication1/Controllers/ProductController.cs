using Microsoft.AspNetCore.Mvc;
using WebApplication1.Data;
using WebApplication1.Models;
using static WebApplication1.Controllers.HomeController;

namespace WebApplication1.Controllers;

public class ProductController : Controller
{
    private readonly DbHelper _db;
    public ProductController(DbHelper db) => _db = db;

    // ── GET /Product ──────────────────────────────────────────────────────────
    public async Task<IActionResult> Index(string? category, string? sort)
    {
        var where = string.IsNullOrEmpty(category) ? "" : $"WHERE Category = '{category}'";
        var order = sort switch
        {
            "price_asc"  => "ORDER BY Price ASC",
            "price_desc" => "ORDER BY Price DESC",
            "newest"     => "ORDER BY CreatedAt DESC",
            _            => "ORDER BY Name ASC"
        };
        // VULNERABLE: SQL Injection via category and sort
        var sql = $"SELECT * FROM Products {where} {order}";
        var rows = await _db.ExecuteQueryAsync(sql);
        var catRows = await _db.ExecuteQueryAsync("SELECT DISTINCT Category FROM Products ORDER BY Category");

        ViewBag.Categories = catRows.Select(r => r["Category"]?.ToString() ?? "").ToList();
        ViewBag.CurrentCategory = category;
        ViewBag.Sort = sort;
        return View(rows.Select(MapProduct).ToList());
    }

    // ── GET /Product/Details/{id} ─────────────────────────────────────────────
    public async Task<IActionResult> Details(int id)
    {
        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Products WHERE Id = {id}");
        if (rows.Count == 0) return NotFound();

        var product = MapProduct(rows[0]);

        var reviewRows = await _db.ExecuteQueryAsync(
            $"SELECT * FROM Reviews WHERE ProductId = {id} ORDER BY CreatedAt DESC");
        product.Reviews = reviewRows.Select(r => new Review
        {
            Id        = Convert.ToInt32(r["Id"]),
            ProductId = id,
            UserId    = Convert.ToInt32(r["UserId"]),
            Username  = r["Username"]?.ToString() ?? "",
            Rating    = Convert.ToInt32(r["Rating"]),
            Comment   = r["Comment"]?.ToString() ?? "",
            CreatedAt = Convert.ToDateTime(r["CreatedAt"])
        }).ToList();

        return View(product);
    }

    // ── POST /Product/AddReview ───────────────────────────────────────────────
    [HttpPost]
    public async Task<IActionResult> AddReview(int productId, int rating, string comment)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login", "Account");

        var username = HttpContext.Session.GetString("Username") ?? "anonymous";

        // VULNERABLE: SQL Injection via comment field
        var sql = $"INSERT INTO Reviews (ProductId, UserId, Username, Rating, Comment) VALUES ({productId}, {userId}, '{username}', {rating}, '{comment}')";
        await _db.ExecuteNonQueryAsync(sql);

        return RedirectToAction("Details", new { id = productId });
    }

    // ── POST /Product/Import — VULNERABLE: XXE ───────────────────────────────
    [HttpPost]
    public async Task<IActionResult> Import(IFormFile xmlFile)
    {
        if (xmlFile == null || xmlFile.Length == 0)
        {
            TempData["Error"] = "Please upload an XML file.";
            return RedirectToAction("Index", "Admin");
        }

        using var stream = xmlFile.OpenReadStream();
        using var reader = new System.IO.StreamReader(stream);
        var xmlContent = await reader.ReadToEndAsync();

        // VULNERABLE: XXE — external entities enabled via XmlUrlResolver
        // Payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        //          <products><product><name>&xxe;</name>...</product></products>
        var xmlDoc = new System.Xml.XmlDocument();
        xmlDoc.XmlResolver = new System.Xml.XmlUrlResolver(); // enables external entities
        xmlDoc.LoadXml(xmlContent);

        var imported = 0;
        var nodes = xmlDoc.SelectNodes("//product");
        if (nodes != null)
        {
            foreach (System.Xml.XmlNode node in nodes)
            {
                var name     = node["name"]?.InnerText?.Replace("'", "''") ?? "Unknown";
                var desc     = node["description"]?.InnerText?.Replace("'", "''") ?? "";
                var price    = node["price"]?.InnerText ?? "0";
                var stock    = node["stock"]?.InnerText ?? "0";
                var category = node["category"]?.InnerText?.Replace("'", "''") ?? "General";
                var imageUrl = node["imageUrl"]?.InnerText?.Replace("'", "''") ?? "";

                var sql = $"INSERT INTO Products (Name, Description, Price, Stock, Category, ImageUrl) VALUES ('{name}', '{desc}', {price}, {stock}, '{category}', '{imageUrl}')";
                await _db.ExecuteNonQueryAsync(sql);
                imported++;
            }
        }

        TempData["Success"] = $"Imported {imported} product(s).";
        return RedirectToAction("Index", "Admin");
    }

    private static Product MapProduct(Dictionary<string, object?> r) =>
        HomeController.MapProduct(r);
}
