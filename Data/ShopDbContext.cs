using Microsoft.EntityFrameworkCore;
using WebApp1.Models;

namespace WebApp1.Data;

public class ShopDbContext : DbContext
{
    public ShopDbContext(DbContextOptions<ShopDbContext> options) : base(options)
    {
    }

    public DbSet<Product> Products { get; set; }
    public DbSet<User> Users { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<OrderItem> OrderItems { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Product>().HasData(
            new Product { Id = 1, Name = "Laptop", Description = "High-performance laptop", Price = 999.99m, Stock = 10, Category = "Electronics", ImageUrl = "/images/laptop.jpg" },
            new Product { Id = 2, Name = "Smartphone", Description = "Latest smartphone model", Price = 699.99m, Stock = 20, Category = "Electronics", ImageUrl = "/images/phone.jpg" },
            new Product { Id = 3, Name = "Headphones", Description = "Wireless headphones", Price = 149.99m, Stock = 30, Category = "Electronics", ImageUrl = "/images/headphones.jpg" },
            new Product { Id = 4, Name = "Mouse", Description = "Gaming mouse", Price = 49.99m, Stock = 50, Category = "Accessories", ImageUrl = "/images/mouse.jpg" },
            new Product { Id = 5, Name = "Keyboard", Description = "Mechanical keyboard", Price = 129.99m, Stock = 25, Category = "Accessories", ImageUrl = "/images/keyboard.jpg" }
        );

        modelBuilder.Entity<User>().HasData(
            new User { Id = 1, Username = "admin", Password = "admin123", Email = "admin@shop.com", IsAdmin = true },
            new User { Id = 2, Username = "john", Password = "password", Email = "john@example.com", IsAdmin = false }
        );
    }
}
