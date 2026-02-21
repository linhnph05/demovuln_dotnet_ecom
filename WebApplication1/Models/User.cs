namespace WebApplication1.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;  
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "user";
    public string Address { get; set; } = string.Empty;
    public string Phone { get; set; } = string.Empty;
    public string? ProfileData { get; set; }
    public string? AvatarUrl { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
