using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;

namespace WebApp1.Pages;

public class LoginModel : PageModel
{
    private readonly string _connectionString;

    public LoginModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password))
        {
            ErrorMessage = "Username and password are required.";
            return Page();
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var query = $"SELECT * FROM Users WHERE Username = '{Username}' AND Password = '{Password}'";
        
        using var command = new SqliteCommand(query, connection);
        using var reader = command.ExecuteReader();

        if (reader.Read())
        {
            HttpContext.Session.SetString("Username", Username);
            HttpContext.Session.SetString("IsAdmin", reader.GetBoolean(4).ToString());
            return RedirectToPage("/Index");
        }

        ErrorMessage = "Invalid username or password.";
        return Page();
    }
}
