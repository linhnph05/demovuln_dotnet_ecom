using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;

namespace WebApp1.Pages;

public class SignUpModel : PageModel
{
    private readonly string _connectionString;

    public SignUpModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=shop.db";
    }

    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    [BindProperty]
    public string? ConfirmPassword { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    public void OnGet()
    {
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password) || string.IsNullOrEmpty(Email))
        {
            ErrorMessage = "All fields are required.";
            return Page();
        }

        if (Password != ConfirmPassword)
        {
            ErrorMessage = "Passwords do not match.";
            return Page();
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var checkQuery = $"SELECT COUNT(*) FROM Users WHERE Username = '{Username}'";
        using var checkCommand = new SqliteCommand(checkQuery, connection);
        var userExists = Convert.ToInt32(checkCommand.ExecuteScalar()) > 0;

        if (userExists)
        {
            ErrorMessage = "Username already exists.";
            return Page();
        }

        var insertQuery = $"INSERT INTO Users (Username, Password, Email, IsAdmin) VALUES ('{Username}', '{Password}', '{Email}', 0)";
        using var insertCommand = new SqliteCommand(insertQuery, connection);
        insertCommand.ExecuteNonQuery();

        SuccessMessage = "Account created successfully! You can now login.";
        return Page();
    }
}
