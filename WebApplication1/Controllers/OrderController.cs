using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using PuppeteerSharp;
using WebApplication1.Data;
using WebApplication1.Models;
using System.Net.Http;

namespace WebApplication1.Controllers;

public class OrderController : Controller
{
    private readonly DbHelper _db;
    public OrderController(DbHelper db) => _db = db;

    public async Task<IActionResult> Index(string? status)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login", "Account");

        var where = string.IsNullOrEmpty(status)
            ? $"WHERE UserId = {userId}"
            : $"WHERE UserId = {userId} AND Status = '{status}'";

        var sql = $"SELECT * FROM Orders {where} ORDER BY CreatedAt DESC";
        var rows = await _db.ExecuteQueryAsync(sql);

        var orders = rows.Select(r => new Order
        {
            Id = Convert.ToInt32(r["Id"]),
            UserId = Convert.ToInt32(r["UserId"]),
            TotalAmount = Convert.ToDecimal(r["TotalAmount"]),
            Status = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes = r["Notes"]?.ToString(),
            CreatedAt = Convert.ToDateTime(r["CreatedAt"])
        }).ToList();

        ViewBag.CurrentStatus = status;
        return View(orders);
    }

    public async Task<IActionResult> Details(int id)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login", "Account");

        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Orders WHERE Id = {id}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var order = new Order
        {
            Id = Convert.ToInt32(r["Id"]),
            UserId = Convert.ToInt32(r["UserId"]),
            TotalAmount = Convert.ToDecimal(r["TotalAmount"]),
            Status = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes = r["Notes"]?.ToString(),
            CreatedAt = Convert.ToDateTime(r["CreatedAt"])
        };

        var itemRows = await _db.ExecuteQueryAsync($"SELECT * FROM OrderItems WHERE OrderId = {id}");
        order.Items = itemRows.Select(ir => new OrderItem
        {
            Id = Convert.ToInt32(ir["Id"]),
            OrderId = id,
            ProductId = Convert.ToInt32(ir["ProductId"]),
            ProductName = ir["ProductName"]?.ToString() ?? "",
            Quantity = Convert.ToInt32(ir["Quantity"]),
            UnitPrice = Convert.ToDecimal(ir["UnitPrice"])
        }).ToList();

        return View(order);
    }

    [HttpPost]
    public async Task<IActionResult> Checkout(string shippingAddress, string? notes)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login", "Account");

        var cartCookie = Request.Cookies["shopvuln_cart"];
        if (string.IsNullOrEmpty(cartCookie))
        {
            TempData["Error"] = "Your cart is empty.";
            return RedirectToAction("Index", "Cart");
        }

        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var cart = JsonConvert.DeserializeObject<Cart>(cartCookie, settings);
        if (cart == null || cart.Items.Count == 0)
        {
            TempData["Error"] = "Your cart is empty.";
            return RedirectToAction("Index", "Cart");
        }

        var addr = shippingAddress.Replace("'", "''");
        var note = notes?.Replace("'", "''") ?? "";
        var total = cart.Total;

        var orderSql = $"INSERT INTO Orders (UserId, TotalAmount, Status, ShippingAddress, Notes) VALUES ({userId}, {total}, 'Pending', '{addr}', '{note}')";
        var orderId = (int)await _db.ExecuteInsertAsync(orderSql);

        foreach (var item in cart.Items)
        {
            var name = item.ProductName.Replace("'", "''");
            var itemSql = $"INSERT INTO OrderItems (OrderId, ProductId, ProductName, Quantity, UnitPrice) VALUES ({orderId}, {item.ProductId}, '{name}', {item.Quantity}, {item.Price})";
            await _db.ExecuteNonQueryAsync(itemSql);
        }

        Response.Cookies.Delete("shopvuln_cart");
        return RedirectToAction("Details", new { id = orderId });
    }

    [HttpPost]
    public async Task<IActionResult> DownloadInvoice(int orderId)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return Unauthorized();

        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Orders WHERE Id = {orderId}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var order = new Order
        {
            Id = Convert.ToInt32(r["Id"]),
            TotalAmount = Convert.ToDecimal(r["TotalAmount"]),
            Status = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes = r["Notes"]?.ToString(),
            CreatedAt = Convert.ToDateTime(r["CreatedAt"])
        };

        var itemRows = await _db.ExecuteQueryAsync($"SELECT * FROM OrderItems WHERE OrderId = {orderId}");
        order.Items = itemRows.Select(ir => new OrderItem
        {
            ProductName = ir["ProductName"]?.ToString() ?? "",
            Quantity = Convert.ToInt32(ir["Quantity"]),
            UnitPrice = Convert.ToDecimal(ir["UnitPrice"])
        }).ToList();

        var logoHtml = "<div style='width:80px;height:55px;background:#6c63ff;display:flex;align-items:center;justify-content:center;color:white;font-size:18px;font-weight:bold;'>SV</div>";

        var itemsHtml = string.Join("", order.Items.Select((item, idx) =>
        {
            var bg = idx % 2 == 0 ? "#fff" : "#f8fafc";
            return $@"<tr style='background:{bg}'>
                <td style='padding:7px;border-bottom:1px solid #e2e8f0'>{item.ProductName}</td>
                <td style='padding:7px;text-align:center;border-bottom:1px solid #e2e8f0'>{item.Quantity}</td>
                <td style='padding:7px;text-align:right;border-bottom:1px solid #e2e8f0'>${item.UnitPrice:N2}</td>
                <td style='padding:7px;text-align:right;border-bottom:1px solid #e2e8f0'>${item.Quantity * item.UnitPrice:N2}</td>
            </tr>";
        }));

        var invoiceData = $@"<!DOCTYPE html>
<html><head><meta charset='utf-8'/><style>body{{font-family:Arial,sans-serif;font-size:11px;margin:50px}}</style></head><body>
<div style='display:flex;justify-content:space-between;align-items:start;margin-bottom:20px;border-bottom:1px solid #e2e8f0;padding-bottom:10px'>
  <div style='display:flex;gap:16px'>{logoHtml}
    <div><div style='font-size:24px;font-weight:bold;color:#0f172a'>INVOICE</div>
    <div style='color:#6c63ff'>#{order.Id:D6}</div></div>
  </div>
  <div style='text-align:right;font-size:9px;color:#64748b'>
    <div>Date: {order.CreatedAt:yyyy-MM-dd}</div><div>Status: {order.Status}</div>
  </div>
</div>
<div style='background:#f8fafc;padding:10px;margin-bottom:16px'>
  <div style='font-weight:bold;font-size:9px;color:#64748b'>BILL TO</div>
  <div style='margin-top:4px'>{order.ShippingAddress}</div>
</div>
<table style='width:100%;border-collapse:collapse;margin-bottom:10px'>
  <thead><tr style='background:#0f172a;color:white'>
    <th style='padding:7px;text-align:left;font-size:10px'>Product</th>
    <th style='padding:7px;text-align:center;font-size:10px'>Qty</th>
    <th style='padding:7px;text-align:right;font-size:10px'>Unit Price</th>
    <th style='padding:7px;text-align:right;font-size:10px'>Total</th>
  </tr></thead>
  <tbody>{itemsHtml}</tbody>
</table>
<div style='text-align:right;margin-bottom:20px'>
  <div style='display:inline-block;width:220px'>
    <div style='display:flex;justify-content:space-between;padding:3px 0;color:#64748b'><span>Subtotal</span><span>${order.TotalAmount:N2}</span></div>
    <div style='display:flex;justify-content:space-between;padding:3px 0;color:#64748b'><span>Shipping</span><span style='color:#16a34a'>FREE</span></div>
    <div style='border-top:1px solid #e2e8f0;margin:3px 0'></div>
    <div style='display:flex;justify-content:space-between;padding:3px 0;font-weight:bold;font-size:13px'><span>Total</span><span style='color:#6c63ff'>${order.TotalAmount:N2}</span></div>
  </div>
</div>
<div style='text-align:center;font-size:8px;color:#94a3b8;margin-top:30px'>ShopVuln Store · Invoice #{order.Id:D6}</div>
</body></html>";

        try
        {
            // Launch browser with Chrome installed in Docker container
            var browser = await Puppeteer.LaunchAsync(new LaunchOptions
            {
                Headless = true,
                ExecutablePath = "/usr/bin/google-chrome-stable",
                Args = new[] {
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-accelerated-2d-canvas",
                    "--no-first-run",
                    "--no-zygote",
                    "--disable-gpu"
                }
            });

            var page = await browser.NewPageAsync();

            // Set content from invoice data
            await page.SetContentAsync(invoiceData);

            // Generate PDF
            var pdf = await page.PdfDataAsync(new PdfOptions
            {
                Format = PuppeteerSharp.Media.PaperFormat.A4,
                PrintBackground = true
            });

            await browser.CloseAsync();

            return File(pdf, "application/pdf", $"invoice-{orderId}.pdf");
        }
        catch (Exception error)
        {
            Console.WriteLine(error);
            return StatusCode(500, "PDF generation failed");
        }
    }

    [HttpGet]
    public async Task<IActionResult> Receipt(int id)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login", "Account");

        var rows = await _db.ExecuteQueryAsync(
            $"SELECT o.*, u.Username, u.Email, u.FullName " +
            $"FROM Orders o JOIN Users u ON o.UserId = u.Id " +
            $"WHERE o.Id = {id}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var itemRows = await _db.ExecuteQueryAsync($"SELECT * FROM OrderItems WHERE OrderId = {id}");

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("================================================");
        sb.AppendLine("         SHOPVULN — ORDER RECEIPT               ");
        sb.AppendLine("================================================");
        sb.AppendLine($"Receipt No : {id}");
        sb.AppendLine($"Date       : {Convert.ToDateTime(r["CreatedAt"]):yyyy-MM-dd HH:mm}");
        sb.AppendLine($"Status     : {r["Status"]}");
        sb.AppendLine("------------------------------------------------");
        sb.AppendLine("Customer Information: ");
        sb.AppendLine($"  Full Name : {r["FullName"]}");
        sb.AppendLine($"  Email     : {r["Email"]}");
        sb.AppendLine($"  Username  : {r["Username"]}");
        sb.AppendLine("------------------------------------------------");
        sb.AppendLine("Shipping Address:");
        sb.AppendLine($"  {r["ShippingAddress"]}");
        sb.AppendLine("------------------------------------------------");
        sb.AppendLine($"  {"Product",-30} {"Qty",4}  {"Unit Price",10}  {"Total",10}");
        sb.AppendLine($"  {new string('-', 58)}");
        foreach (var ir in itemRows)
        {
            var qty = Convert.ToInt32(ir["Quantity"]);
            var price = Convert.ToDecimal(ir["UnitPrice"]);
            sb.AppendLine($"  {ir["ProductName"],-30} {qty,4}  {$"${price:N2}",10}  {$"${qty * price:N2}",10}");
        }
        sb.AppendLine("------------------------------------------------");
        sb.AppendLine($"  {"Order Total:",46} {$"${Convert.ToDecimal(r["TotalAmount"]):N2}",10}");
        sb.AppendLine("================================================");

        var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
        return File(bytes, "text/plain", $"receipt-{id}.txt");
    }
}
