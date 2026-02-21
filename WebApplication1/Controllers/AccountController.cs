using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Controllers;

public class AccountController : Controller
{
    private readonly DbHelper _db;
    public AccountController(DbHelper db) => _db = db;

    [HttpGet]
    public IActionResult Login(string? returnUrl)
    {
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password, string? returnUrl)
    {
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
            Id          = Convert.ToInt32(r["Id"]),
            Username    = r["Username"]?.ToString() ?? "",
            Email       = r["Email"]?.ToString() ?? "",
            FullName    = r["FullName"]?.ToString() ?? "",
            Address     = r["Address"]?.ToString() ?? "",
            Phone       = r["Phone"]?.ToString() ?? "",
            Role        = r["Role"]?.ToString() ?? "user",
            ProfileData = r.TryGetValue("ProfileData", out var pd) ? pd?.ToString() : null,
            AvatarUrl   = r.TryGetValue("AvatarUrl",   out var av) ? av?.ToString() : null
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
        var savePath  = Path.Combine(uploadsDir, fileName);

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
                FileName               = "/bin/bash",
                Arguments              = $"-c \"convert {filePath} -resize 256x256^ -gravity Center -extent 256x256 {filePath} 2>&1\"",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using (var proc = Process.Start(resize)!) proc.WaitForExit(10000);
            var identify = new ProcessStartInfo
            {
                FileName               = "/bin/bash",
                Arguments              = $"-c \"identify -verbose {filePath} 2>&1 | grep -E 'Format|Geometry|Filesize'\"",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var ip = Process.Start(identify)!;
            var info = ip.StandardOutput.ReadToEnd() + ip.StandardError.ReadToEnd();
            ip.WaitForExit(5000);
            return string.IsNullOrWhiteSpace(info) ? "Image resized to 256×256." : info.Trim();
        }
        catch (Exception ex) { return $"[error: {ex.Message}]"; }
    }

    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }
}
