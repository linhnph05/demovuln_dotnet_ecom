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

    // ── POST /Account/Profile ── VULNERABLE: Insecure Deserialization ─────────
    [HttpPost]
    public async Task<IActionResult> Profile(string fullName, string email, string address, string phone, string? profileData)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToAction("Login");

        // VULNERABLE: Insecure Deserialization — TypeNameHandling.All deserialises
        // user-supplied JSON and instantiates arbitrary .NET types via $type.
        // Exploit using ysoserial.net: -g ObjectDataProvider -f Json.Net -c "cmd /c ..."
        if (!string.IsNullOrEmpty(profileData))
        {
            try
            {
                var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
                _ = JsonConvert.DeserializeObject(profileData, settings);
            }
            catch { /* swallow — side-effects already triggered */ }
        }

        var escapedProfileData = profileData?.Replace("'", "''") ?? "";
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

        // VULNERABLE: client-supplied filename used directly — no sanitisation.
        // Enables both path traversal (../../evil) and shell injection when the
        // filename is later passed to the file(1) command below.
        var fileName = Path.GetFileName(avatarFile.FileName); // GetFileName still keeps injections like "x.jpg; id"
        var savePath  = Path.Combine(uploadsDir, fileName);

        await using (var fs = new FileStream(savePath, FileMode.Create))
            await avatarFile.CopyToAsync(fs);

        // VULNERABLE: Command Injection — savePath contains the unsanitised filename.
        // Example filename:  photo.jpg; whoami; #
        // Shell sees:        file -b /app/.../photo.jpg; whoami; #
        var fileInfo = RunFileCommand(savePath);

        var avatarUrl = $"/uploads/avatars/{fileName}";
        // SQL injection also present in the UPDATE
        await _db.ExecuteNonQueryAsync(
            $"UPDATE Users SET AvatarUrl='{avatarUrl.Replace("'", "''")}' WHERE Id={userId}");

        TempData["Success"] = $"Avatar uploaded. Server analysis: {fileInfo}";
        return RedirectToAction("Profile");
    }

    // ── Shared helper: intentionally vulnerable to command injection ───────────
    private static string RunFileCommand(string filePath)
    {
        // VULNERABLE: filePath is built from unsanitised user input and interpolated
        // directly into the shell argument string.  No quoting, no escaping.
        //
        // Safe version would be:  Arguments = $"-b --", with filePath as a separate arg.
        // Vulnerable version:     Arguments = $"-c \"file -b {filePath} 2>&1\""
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName               = "/bin/bash",
                Arguments              = $"-c \"file -b {filePath} 2>&1\"",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);
            return output.Trim();
        }
        catch (Exception ex) { return $"[error: {ex.Message}]"; }
    }

    // ── GET /Account/Logout ───────────────────────────────────────────────────
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }
}
