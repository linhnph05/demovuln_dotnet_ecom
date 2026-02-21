using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Controllers;

public class CartController : Controller
{
    private readonly DbHelper _db;
    private const string CookieName = "shopvuln_cart";

    public CartController(DbHelper db) => _db = db;

    public IActionResult Index()
    {
        var cart = GetCart();
        return View(cart);
    }

    [HttpPost]
    public async Task<IActionResult> Add(int productId, int quantity = 1)
    {
        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Products WHERE Id = {productId}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var cart = GetCart();
        var existing = cart.Items.FirstOrDefault(i => i.ProductId == productId);
        if (existing != null)
            existing.Quantity += quantity;
        else
            cart.Items.Add(new CartItem
            {
                ProductId   = productId,
                ProductName = r["Name"]?.ToString() ?? "",
                Price       = Convert.ToDecimal(r["Price"]),
                Quantity    = quantity,
                ImageUrl    = r["ImageUrl"]?.ToString() ?? ""
            });

        SaveCart(cart);
        TempData["Success"] = "Item added to cart.";
        return RedirectToAction("Index");
    }

    [HttpPost]
    public IActionResult Update([FromForm] string cartJson)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        try
        {
            var cart = JsonConvert.DeserializeObject<Cart>(cartJson, settings);
            if (cart != null) SaveCart(cart);
        }
        catch { }

        return RedirectToAction("Index");
    }

    [HttpPost]
    public IActionResult Remove(int productId)
    {
        var cart = GetCart();
        cart.Items.RemoveAll(i => i.ProductId == productId);
        SaveCart(cart);
        return RedirectToAction("Index");
    }

    [HttpPost]
    public IActionResult Clear()
    {
        Response.Cookies.Delete(CookieName);
        return RedirectToAction("Index");
    }

    private Cart GetCart()
    {
        var cookieVal = Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(cookieVal)) return new Cart();

        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        return JsonConvert.DeserializeObject<Cart>(cookieVal, settings) ?? new Cart();
    }

    private void SaveCart(Cart cart)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var json = JsonConvert.SerializeObject(cart, settings);
        Response.Cookies.Append(CookieName, json, new CookieOptions
        {
            Expires = DateTimeOffset.UtcNow.AddDays(7),
            HttpOnly = false 
        });
    }
}
