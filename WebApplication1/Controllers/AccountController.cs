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

                // Normal functionality: validate and normalize JSON before storing.
                // NOTE: still intentionally vulnerable because deserialization keeps TypeNameHandling.All.
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

    // ── POST /Account/UploadAvatar ─────────────────────────────────────────────
    // VULNERABLE 1 — Unrestricted File Upload:
    //   No extension whitelist, no MIME check, no size limit enforced.
    //   Upload shell.aspx / shell.php / shell.sh — file lands in wwwroot/uploads/avatars/
    //   and is directly reachable at GET /uploads/avatars/shell.aspx
    //
    // VULNERABLE 2 — Command Injection via filename:
    //   The original client-supplied filename is interpolated into a bash command:
    //     file -b /app/wwwroot/uploads/avatars/<FILENAME>
    //   Upload a file named:  x.jpg; id; #
    //   → bash executes:      file -b x.jpg; id; #
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

        // Use generated server-side filename to avoid collisions and traversal issues.
        var fileName = $"{Guid.NewGuid():N}.jpg";
        var savePath = Path.Combine(uploadsDir, fileName);
        var tempInputPath = Path.Combine(uploadsDir, $"{Guid.NewGuid():N}{Path.GetExtension(avatarFile.FileName)}");

        await using (var fs = new FileStream(tempInputPath, FileMode.Create))
            await avatarFile.CopyToAsync(fs);

        // Resize/compress avatar to a practical web format (max 512x512 JPEG).
        var (ok, commandOutput) = RunImageOptimizeCommand(tempInputPath, savePath);
        System.IO.File.Delete(tempInputPath);

        if (!ok)
        {
            TempData["Error"] = $"Could not process image. {commandOutput}";
            return RedirectToAction("Profile");
        }

        var avatarUrl = $"/uploads/avatars/{fileName}";
        // SQL injection also present in the UPDATE
        await _db.ExecuteNonQueryAsync(
            $"UPDATE Users SET AvatarUrl='{avatarUrl.Replace("'", "''")}' WHERE Id={userId}");

        TempData["Success"] = "Avatar uploaded and optimized successfully.";
        return RedirectToAction("Profile");
    }

    // Uses ImageMagick to optimize avatars: auto-orient, strip metadata,
    // resize to max 512x512 and compress to quality 82 JPEG.
    private static (bool Success, string Output) RunImageOptimizeCommand(string inputPath, string outputPath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName               = "magick",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };

            psi.ArgumentList.Add(inputPath);
            psi.ArgumentList.Add("-auto-orient");
            psi.ArgumentList.Add("-strip");
            psi.ArgumentList.Add("-resize");
            psi.ArgumentList.Add("512x512>");
            psi.ArgumentList.Add("-quality");
            psi.ArgumentList.Add("82");
            psi.ArgumentList.Add(outputPath);

            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);
            return (proc.ExitCode == 0, output.Trim());
        }
        catch (Exception ex) { return (false, $"[error: {ex.Message}]"); }
    }

    // ── GET /Account/Logout ───────────────────────────────────────────────────
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }
}
