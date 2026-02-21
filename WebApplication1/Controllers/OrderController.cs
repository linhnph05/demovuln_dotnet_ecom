using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using WebApplication1.Data;
using WebApplication1.Models;

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
            Id              = Convert.ToInt32(r["Id"]),
            UserId          = Convert.ToInt32(r["UserId"]),
            TotalAmount     = Convert.ToDecimal(r["TotalAmount"]),
            Status          = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes           = r["Notes"]?.ToString(),
            CreatedAt       = Convert.ToDateTime(r["CreatedAt"])
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
            Id              = Convert.ToInt32(r["Id"]),
            UserId          = Convert.ToInt32(r["UserId"]),
            TotalAmount     = Convert.ToDecimal(r["TotalAmount"]),
            Status          = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes           = r["Notes"]?.ToString(),
            CreatedAt       = Convert.ToDateTime(r["CreatedAt"])
        };

        var itemRows = await _db.ExecuteQueryAsync($"SELECT * FROM OrderItems WHERE OrderId = {id}");
        order.Items = itemRows.Select(ir => new OrderItem
        {
            Id          = Convert.ToInt32(ir["Id"]),
            OrderId     = id,
            ProductId   = Convert.ToInt32(ir["ProductId"]),
            ProductName = ir["ProductName"]?.ToString() ?? "",
            Quantity    = Convert.ToInt32(ir["Quantity"]),
            UnitPrice   = Convert.ToDecimal(ir["UnitPrice"])
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

        var addr  = shippingAddress.Replace("'", "''");
        var note  = notes?.Replace("'", "''") ?? "";
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
    public async Task<IActionResult> DownloadInvoice(int orderId, string? logoUrl)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return Unauthorized();

        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Orders WHERE Id = {orderId}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var order = new Order
        {
            Id              = Convert.ToInt32(r["Id"]),
            TotalAmount     = Convert.ToDecimal(r["TotalAmount"]),
            Status          = r["Status"]?.ToString() ?? "",
            ShippingAddress = r["ShippingAddress"]?.ToString() ?? "",
            Notes           = r["Notes"]?.ToString(),
            CreatedAt       = Convert.ToDateTime(r["CreatedAt"])
        };

        var itemRows = await _db.ExecuteQueryAsync($"SELECT * FROM OrderItems WHERE OrderId = {orderId}");
        order.Items = itemRows.Select(ir => new OrderItem
        {
            ProductName = ir["ProductName"]?.ToString() ?? "",
            Quantity    = Convert.ToInt32(ir["Quantity"]),
            UnitPrice   = Convert.ToDecimal(ir["UnitPrice"])
        }).ToList();

        byte[] logoBytes  = [];
        string ssrfStatus = "No logo URL provided.";
        string remoteBody = "";

        if (!string.IsNullOrEmpty(logoUrl))
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                var resp     = await http.GetAsync(logoUrl);                         
                var rawBytes = await resp.Content.ReadAsByteArrayAsync();
                var ct       = resp.Content.Headers.ContentType?.MediaType ?? "";
                ssrfStatus   = $"HTTP {(int)resp.StatusCode} {resp.StatusCode} | {rawBytes.Length} bytes | {ct}";

                if (ct.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                    logoBytes = rawBytes;
                else
                    remoteBody = System.Text.Encoding.UTF8.GetString(rawBytes);
            }
            catch (Exception ex)
            {
                ssrfStatus = $"[{ex.GetType().Name}] {ex.Message}";
                remoteBody = ex.ToString();
            }
        }

        var pdf = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(50);
                page.DefaultTextStyle(x => x.FontSize(11));

                page.Header().Column(hdr =>
                {
                    hdr.Item().Row(hRow =>
                    {
                        if (logoBytes.Length > 0)
                            hRow.ConstantItem(80).Height(55).Image(logoBytes).FitArea();
                        else
                            hRow.ConstantItem(80).Height(55)
                                .Background("#6c63ff").AlignCenter().AlignMiddle()
                                .DefaultTextStyle(x => x.FontSize(18).Bold().FontColor("#ffffff"))
                                .Text("SV");

                        hRow.RelativeItem().PaddingLeft(16).Column(c =>
                        {
                            c.Item().DefaultTextStyle(x => x.FontSize(24).Bold().FontColor("#0f172a")).Text("INVOICE");
                            c.Item().DefaultTextStyle(x => x.FontColor("#6c63ff")).Text($"#{order.Id:D6}");
                        });

                        hRow.ConstantItem(140).AlignRight().Column(c =>
                        {
                            c.Item().DefaultTextStyle(x => x.FontSize(9).FontColor("#64748b")).Text($"Date:   {order.CreatedAt:yyyy-MM-dd}");
                            c.Item().DefaultTextStyle(x => x.FontSize(9).FontColor("#64748b")).Text($"Status: {order.Status}");
                        });
                    });
                    hdr.Item().PaddingTop(8).LineHorizontal(1).LineColor("#e2e8f0");
                });

                page.Content().PaddingTop(16).Column(col =>
                {
                    col.Item().Background("#f8fafc").Padding(10).Column(bt =>
                    {
                        bt.Item().DefaultTextStyle(x => x.Bold().FontSize(9).FontColor("#64748b")).Text("BILL TO");
                        bt.Item().PaddingTop(4).Text(order.ShippingAddress);
                    });

                    col.Item().PaddingTop(16).Table(table =>
                    {
                        table.ColumnsDefinition(cols =>
                        {
                            cols.RelativeColumn(4);
                            cols.RelativeColumn(1);
                            cols.RelativeColumn(2);
                            cols.RelativeColumn(2);
                        });

                        table.Header(h =>
                        {
                            h.Cell().Background("#0f172a").Padding(7)
                                .DefaultTextStyle(x => x.Bold().FontColor("#ffffff").FontSize(10)).Text("Product");
                            h.Cell().Background("#0f172a").Padding(7).AlignCenter()
                                .DefaultTextStyle(x => x.Bold().FontColor("#ffffff").FontSize(10)).Text("Qty");
                            h.Cell().Background("#0f172a").Padding(7).AlignRight()
                                .DefaultTextStyle(x => x.Bold().FontColor("#ffffff").FontSize(10)).Text("Unit Price");
                            h.Cell().Background("#0f172a").Padding(7).AlignRight()
                                .DefaultTextStyle(x => x.Bold().FontColor("#ffffff").FontSize(10)).Text("Total");
                        });

                        var rowIdx = 0;
                        foreach (var item in order.Items)
                        {
                            var bg = rowIdx++ % 2 == 0 ? "#ffffff" : "#f8fafc";
                            table.Cell().Background(bg).BorderBottom(1).BorderColor("#e2e8f0").Padding(7).Text(item.ProductName);
                            table.Cell().Background(bg).BorderBottom(1).BorderColor("#e2e8f0").Padding(7).AlignCenter().Text(item.Quantity.ToString());
                            table.Cell().Background(bg).BorderBottom(1).BorderColor("#e2e8f0").Padding(7).AlignRight().Text($"${item.UnitPrice:N2}");
                            table.Cell().Background(bg).BorderBottom(1).BorderColor("#e2e8f0").Padding(7).AlignRight().Text($"${item.Quantity * item.UnitPrice:N2}");
                        }
                    });

                    col.Item().PaddingTop(10).AlignRight().Width(220).Column(totals =>
                    {
                        totals.Item().PaddingVertical(3).Row(tr =>
                        {
                            tr.RelativeItem().DefaultTextStyle(x => x.FontColor("#64748b")).Text("Subtotal");
                            tr.ConstantItem(90).AlignRight().Text($"${order.TotalAmount:N2}");
                        });
                        totals.Item().PaddingVertical(3).Row(tr =>
                        {
                            tr.RelativeItem().DefaultTextStyle(x => x.FontColor("#64748b")).Text("Shipping");
                            tr.ConstantItem(90).AlignRight().DefaultTextStyle(x => x.FontColor("#16a34a")).Text("FREE");
                        });
                        totals.Item().LineHorizontal(1).LineColor("#e2e8f0");
                        totals.Item().PaddingVertical(3).Row(tr =>
                        {
                            tr.RelativeItem().DefaultTextStyle(x => x.Bold().FontSize(13)).Text("Total");
                            tr.ConstantItem(90).AlignRight()
                                .DefaultTextStyle(x => x.Bold().FontSize(13).FontColor("#6c63ff"))
                                .Text($"${order.TotalAmount:N2}");
                        });
                    });

                    if (!string.IsNullOrEmpty(logoUrl))
                    {
                        col.Item().PaddingTop(24).LineHorizontal(1).LineColor("#fca5a5");
                        col.Item().PaddingTop(8).Background("#fef2f2").Padding(12).Column(s =>
                        {
                            s.Item().DefaultTextStyle(x => x.Bold().FontSize(10).FontColor("#dc2626"))
                                    .Text("Hello");
                            s.Item().PaddingTop(4).DefaultTextStyle(x => x.FontSize(8).FontColor("#475569"))
                                    .Text($"URL:    {logoUrl}");
                            s.Item().DefaultTextStyle(x => x.FontSize(8).FontColor("#475569"))
                                    .Text($"Status: {ssrfStatus}");
                            if (!string.IsNullOrEmpty(remoteBody))
                            {
                                s.Item().PaddingTop(6).DefaultTextStyle(x => x.Bold().FontSize(9).FontColor("#64748b"))
                                        .Text("Response Body:");
                                var truncated = remoteBody.Length > 3000
                                    ? remoteBody[..3000] + "\n\n...[truncated]"
                                    : remoteBody;
                                s.Item().PaddingTop(4).Background("#fff1f2").Padding(8)
                                        .DefaultTextStyle(x => x.FontSize(7.5f).FontColor("#1e293b"))
                                        .Text(truncated);
                            }
                        });
                    }
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.Span("ShopVuln Store  ·  Invoice ").FontSize(8).FontColor("#94a3b8");
                    t.Span($"#{order.Id:D6}").FontSize(8).FontColor("#94a3b8");
                    t.Span("  ·  Page ").FontSize(8).FontColor("#94a3b8");
                    t.CurrentPageNumber().FontSize(8).FontColor("#94a3b8");
                    t.Span(" of ").FontSize(8).FontColor("#94a3b8");
                    t.TotalPages().FontSize(8).FontColor("#94a3b8");
                });
            });
        }).GeneratePdf();

        return File(pdf, "application/pdf", $"invoice-{orderId}.pdf");
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
            var qty   = Convert.ToInt32(ir["Quantity"]);
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
