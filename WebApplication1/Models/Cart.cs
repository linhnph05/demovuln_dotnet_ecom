namespace WebApplication1.Models;

public class Cart
{
    public int UserId { get; set; }
    public List<CartItem> Items { get; set; } = new();
    public decimal Total => Items.Sum(i => i.Price * i.Quantity);
    public int Count => Items.Sum(i => i.Quantity);
}

