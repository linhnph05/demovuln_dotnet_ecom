using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using WebApplication1.Data;
using WebApplication1.Models;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace WebApplication1.Controllers;

public class AccountController : Controller
{
    private readonly DbHelper _db;
    public AccountController(DbHelper db) => _db = db;

    private bool DetectSQLInjection(string input)
    {
        // if (string.IsNullOrEmpty(input)) return false;

        // if (Regex.IsMatch(input,
        //     @"\b(union|select|insert|update|delete|drop|alter|create|truncate|" +
        //     @"exec|execute|xp_|sleep|benchmark|waitfor|concat|char|hex|unhex|" +
        //     @"substr|substring|ascii|ord|conv|extractvalue|updatexml|load_file|" +
        //     @"into\s+(outfile|dumpfile)|information_schema|database|schema|" +
        //     @"Users|administrator)\b",
        //     RegexOptions.IgnoreCase))
        //     return true;

        // //  ' or '   " or 1   1 and '   3 or 2
        // if (Regex.IsMatch(input,
        //     @"['""\d]\s*\b(or|and)\b\s*['""\d]",
        //     RegexOptions.IgnoreCase))
        //     return true;

        // if (input.Contains("--") || input.Contains("#"))
        //     return true;

        // if (input.Contains(";"))
        //     return true;

        return false;
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl)
    {
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password, string? returnUrl)
    {
        // WAF Check
        if (DetectSQLInjection(username) || DetectSQLInjection(password))
        {
            ViewBag.Error = "Potential security threat detected. Request blocked by WAF.";
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        var sql = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";
        var rows = await _db.ExecuteQueryAsync(sql);

        if (rows.Count > 0)
        {
            var user = rows[0];
            HttpContext.Session.SetString("UserId", user["Id"]!.ToString()!);
            HttpContext.Session.SetString("Username", user["Username"]!.ToString()!);
            HttpContext.Session.SetString("Role", user["Role"]?.ToString() ?? "user");
            return Redirect(returnUrl ?? "/");
        }

        ViewBag.Error = "Invalid username or password.";
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    public async Task<IActionResult> Register(string username, string email, string password, string fullName)
    {
        var checkSql = $"SELECT COUNT(*) FROM Users WHERE Username = '{username}'";
        var count = Convert.ToInt32(await _db.ExecuteScalarAsync(checkSql));
        if (count > 0)
        {
            ViewBag.Error = "Username already taken.";
            return View();
        }

        var sql = $"INSERT INTO Users (Username, Email, Password, FullName, Role) VALUES ('{username}', '{email}', '{password}', '{fullName}', 'user')";
        await _db.ExecuteNonQueryAsync(sql);

        return RedirectToAction("Login");
    }

    [HttpGet]
    public async Task<IActionResult> Profile()
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login");

        var rows = await _db.ExecuteQueryAsync($"SELECT * FROM Users WHERE Id = {userId}");
        if (rows.Count == 0) return NotFound();

        var r = rows[0];
        var user = new User
        {
            Id = Convert.ToInt32(r["Id"]),
            Username = r["Username"]?.ToString() ?? "",
            Email = r["Email"]?.ToString() ?? "",
            FullName = r["FullName"]?.ToString() ?? "",
            Address = r["Address"]?.ToString() ?? "",
            Phone = r["Phone"]?.ToString() ?? "",
            Role = r["Role"]?.ToString() ?? "user",
            ProfileData = r.TryGetValue("ProfileData", out var pd) ? pd?.ToString() : null,
            AvatarUrl = r.TryGetValue("AvatarUrl", out var av) ? av?.ToString() : null
        };

        return View(user);
    }

    [HttpPost]
    public async Task<IActionResult> Profile(string fullName, string email, string address, string phone, string? profileData)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login");

        var profileDataToSave = "";

        if (!string.IsNullOrWhiteSpace(profileData))
        {
            try
            {
                var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
                var deserialized = JsonConvert.DeserializeObject(profileData, settings);

                if (deserialized is Dictionary<string, object?> map)
                {
                    if (!map.ContainsKey("theme")) map["theme"] = "light";
                    if (!map.ContainsKey("newsletter")) map["newsletter"] = false;
                }

                profileDataToSave = JsonConvert.SerializeObject(deserialized, Formatting.None);
            }
            catch
            {
                TempData["Error"] = "Preferences must be valid JSON.";
                return RedirectToAction("Profile");
            }
        }

        var escapedProfileData = profileDataToSave.Replace("'", "''");
        var sql = $"UPDATE Users SET FullName='{fullName}', Email='{email}', Address='{address}', Phone='{phone}', ProfileData='{escapedProfileData}' WHERE Id={userId}";
        await _db.ExecuteNonQueryAsync(sql);

        TempData["Success"] = "Profile updated successfully.";
        return RedirectToAction("Profile");
    }

    [HttpPost]
    public async Task<IActionResult> UploadAvatar(IFormFile avatarFile)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login");

        if (avatarFile == null || avatarFile.Length == 0)
        {
            TempData["Error"] = "No file selected.";
            return RedirectToAction("Profile");
        }

        var uploadsDir = Path.Combine(
            Directory.GetCurrentDirectory(), "wwwroot", "uploads", "avatars");
        Directory.CreateDirectory(uploadsDir);

        var fileName = Path.GetFileName(avatarFile.FileName);
        var savePath = Path.Combine(uploadsDir, fileName);

        await using (var fs = new FileStream(savePath, FileMode.Create))
            await avatarFile.CopyToAsync(fs);

        var imageInfo = ProcessUploadedImage(savePath);

        var avatarUrl = $"/uploads/avatars/{fileName}";
        await _db.ExecuteNonQueryAsync(
            $"UPDATE Users SET AvatarUrl='{avatarUrl.Replace("'", "''")}' WHERE Id={userId}");

        TempData["Success"] = $"Avatar uploaded successfully. {imageInfo}";
        return RedirectToAction("Profile");
    }

    private static string ProcessUploadedImage(string filePath)
    {
        try
        {
            var resize = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"convert {filePath} -resize 256x256^ -gravity Center -extent 256x256 {filePath} 2>&1\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(resize)!) proc.WaitForExit(10000);
            var identify = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"identify -verbose {filePath} 2>&1 | grep -E 'Format|Geometry|Filesize'\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var ip = Process.Start(identify)!;
            var info = ip.StandardOutput.ReadToEnd() + ip.StandardError.ReadToEnd();
            ip.WaitForExit(5000);
            return string.IsNullOrWhiteSpace(info) ? "Image resized to 256×256." : info.Trim();
        }
        catch (Exception ex) { return $"[error: {ex.Message}]"; }
    }

    [HttpPost]
    public async Task<IActionResult> SetAvatarFromUrl(string avatarUrl)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login");

        if (string.IsNullOrWhiteSpace(avatarUrl))
        {
            TempData["Error"] = "Avatar URL cannot be empty.";
            return RedirectToAction("Profile");
        }

        // Store the raw URL in database (no validation - SSRF vulnerability)
        await _db.ExecuteNonQueryAsync(
            $"UPDATE Users SET AvatarUrl='{avatarUrl.Replace("'", "''")}' WHERE Id={userId}");

        TempData["Success"] = "Avatar URL saved successfully.";
        return RedirectToAction("Profile");
    }

    [HttpGet]
    public async Task<IActionResult> GetAvatarBase64(string url)
    {
        try
        {
            // SSRF vulnerability: No URL validation, fetches from any URL
            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10);

            var imageBytes = await httpClient.GetByteArrayAsync(url);
            var base64String = Convert.ToBase64String(imageBytes);

            // Determine mime type from URL extension
            var mimeType = "image/png";
            if (url.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                url.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase))
            {
                mimeType = "image/jpeg";
            }
            else if (url.EndsWith(".gif", StringComparison.OrdinalIgnoreCase))
            {
                mimeType = "image/gif";
            }
            else if (url.EndsWith(".webp", StringComparison.OrdinalIgnoreCase))
            {
                mimeType = "image/webp";
            }

            var dataUri = $"data:{mimeType};base64,{base64String}";
            return Content(dataUri, "text/plain");
        }
        catch (Exception ex)
        {
            return Content("", "text/plain");
        }
    }

    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }
}
