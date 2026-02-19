using Microsoft.AspNetCore.Mvc;
using RazorLight;
using WebApplication1.Data;
using WebApplication1.Models;
using static WebApplication1.Controllers.HomeController;

namespace WebApplication1.Controllers;

public class AdminController : Controller
{
    private readonly DbHelper _db;
    public AdminController(DbHelper db) => _db = db;

    private bool IsAdmin() => HttpContext.Session.GetString("Role") == "admin";

    // ── GET /Admin ─────────────────────────────────────────────────────────────
    public async Task<IActionResult> Index()
    {
        if (!IsAdmin()) return RedirectToAction("Login", "Account");

        var userCount    = Convert.ToInt32(await _db.ExecuteScalarAsync("SELECT COUNT(*) FROM Users"));
        var productCount = Convert.ToInt32(await _db.ExecuteScalarAsync("SELECT COUNT(*) FROM Products"));
        var orderCount   = Convert.ToInt32(await _db.ExecuteScalarAsync("SELECT COUNT(*) FROM Orders"));
        var revenue      = await _db.ExecuteScalarAsync("SELECT IFNULL(SUM(TotalAmount),0) FROM Orders WHERE Status='Delivered'");

        ViewBag.UserCount    = userCount;
        ViewBag.ProductCount = productCount;
        ViewBag.OrderCount   = orderCount;
        ViewBag.Revenue      = Convert.ToDecimal(revenue);

        var recentOrders = await _db.ExecuteQueryAsync("SELECT o.*, u.Username FROM Orders o JOIN Users u ON o.UserId=u.Id ORDER BY o.CreatedAt DESC LIMIT 10");
        ViewBag.RecentOrders = recentOrders;

        var products = await _db.ExecuteQueryAsync("SELECT * FROM Products ORDER BY CreatedAt DESC");
        ViewBag.Products = products.Select(MapProduct).ToList();

        return View();
    }

    // ── POST /Admin/UpdateOrderStatus ──────────────────────────────────────────
    [HttpPost]
    public async Task<IActionResult> UpdateOrderStatus(int orderId, string status)
    {
        if (!IsAdmin()) return Unauthorized();
        // VULNERABLE: SQL Injection via status
        await _db.ExecuteNonQueryAsync($"UPDATE Orders SET Status='{status}' WHERE Id={orderId}");
        return RedirectToAction("Index");
    }

    // ── POST /Admin/AddProduct ─────────────────────────────────────────────────
    [HttpPost]
    public async Task<IActionResult> AddProduct(string name, string description, decimal price, int stock, string category, string imageUrl)
    {
        if (!IsAdmin()) return Unauthorized();
        var n = name.Replace("'", "''");
        var d = description.Replace("'", "''");
        var c = category.Replace("'", "''");
        var img = imageUrl.Replace("'", "''");
        await _db.ExecuteNonQueryAsync($"INSERT INTO Products (Name,Description,Price,Stock,Category,ImageUrl) VALUES ('{n}','{d}',{price},{stock},'{c}','{img}')");
        TempData["Success"] = "Product added.";
        return RedirectToAction("Index");
    }

    // ── POST /Admin/DeleteProduct ──────────────────────────────────────────────
    [HttpPost]
    public async Task<IActionResult> DeleteProduct(int id)
    {
        if (!IsAdmin()) return Unauthorized();
        await _db.ExecuteNonQueryAsync($"DELETE FROM Products WHERE Id={id}");
        TempData["Success"] = "Product deleted.";
        return RedirectToAction("Index");
    }

    // ── GET /Admin/Users ───────────────────────────────────────────────────────
    public async Task<IActionResult> Users()
    {
        if (!IsAdmin()) return RedirectToAction("Login", "Account");
        // VULNERABLE: SQL Injection via search
        var search = HttpContext.Request.Query["search"].ToString();
        var sql = string.IsNullOrEmpty(search)
            ? "SELECT Id, Username, Email, FullName, Role, CreatedAt FROM Users ORDER BY CreatedAt DESC"
            : $"SELECT Id, Username, Email, FullName, Role, CreatedAt FROM Users WHERE Username LIKE '%{search}%' OR Email LIKE '%{search}%'";
        var rows = await _db.ExecuteQueryAsync(sql);
        ViewBag.Search = search;
        return View(rows);
    }

    // ── GET /Admin/Tools ── Command Injection + SSTI ──────────────────────────
    [HttpGet]
    public IActionResult Tools()
    {
        if (!IsAdmin()) return RedirectToAction("Login", "Account");
        return View();
    }

    // ── POST /Admin/PreviewTemplate ── VULNERABLE: SSTI via Razor Engine ──────
    /// <summary>
    /// User-supplied Razor template compiled and rendered at runtime by RazorLight.
    /// No sandbox — full .NET API access inside @{ } code blocks.
    ///
    /// Payloads:
    ///   File read : @System.IO.File.ReadAllText("/etc/passwd")
    ///   Env vars  : @System.Environment.GetEnvironmentVariable("PATH")
    ///   RCE       : @{ var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/bin/bash","-c id"){RedirectStandardOutput=true,UseShellExecute=false}); }@p.StandardOutput.ReadToEnd()
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> PreviewTemplate(string template)
    {
        if (!IsAdmin()) return Unauthorized();

        var result = await RenderRazorTemplate(template);
        return Json(new { result });
    }

    private static async Task<string> RenderRazorTemplate(string template)
    {
        try
        {
            // VULNERABLE: SSTI — user-controlled Razor template is compiled and executed
            // by RazorLight at runtime. No sandbox. Full .NET runtime API access.
            // A new unique key per request bypasses the compiled-template cache,
            // ensuring the current input is always freshly compiled and run.
            var engine = new RazorLightEngineBuilder()
                .UseEmbeddedResourcesProject(typeof(AdminController))
                .SetOperatingAssembly(typeof(AdminController).Assembly)
                .UseMemoryCachingProvider()
                .Build();

            return await engine.CompileRenderStringAsync(
                Guid.NewGuid().ToString(),
                template,
                new { });
        }
        catch (Exception ex)
        {
            return $"[Render Error]\n{ex.Message}\n\n{ex.InnerException?.Message}";
        }
    }
}
