using MySqlConnector;

namespace WebApplication1.Data;

/// <summary>
/// Raw ADO.NET database helper.
/// NOTE: Several methods execute unsanitised user input — intentionally vulnerable to SQL Injection.
/// </summary>
public class DbHelper
{
    private readonly string _connectionString;

    public DbHelper(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection")!;
    }

    public MySqlConnection GetConnection() => new(_connectionString);

    // ── Vulnerable: caller is responsible for building the SQL string ──────────
    public async Task<List<Dictionary<string, object?>>> ExecuteQueryAsync(string sql)
    {
        var results = new List<Dictionary<string, object?>>();
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            results.Add(row);
        }
        return results;
    }

    public async Task<int> ExecuteNonQueryAsync(string sql)
    {
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        return await cmd.ExecuteNonQueryAsync();
    }

    public async Task<object?> ExecuteScalarAsync(string sql)
    {
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        var result = await cmd.ExecuteScalarAsync();
        return result == DBNull.Value ? null : result;
    }

    // ── INSERT and return auto-increment ID (same connection) ─────────────────
    /// <summary>
    /// Runs an INSERT statement and returns the auto-generated primary key.
    /// Uses MySqlCommand.LastInsertedId so the ID is read on the same connection,
    /// avoiding the LAST_INSERT_ID()=0 bug that occurs when a new connection is opened.
    /// </summary>
    public async Task<long> ExecuteInsertAsync(string sql)
    {
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
        return cmd.LastInsertedId;
    }

    // ── Safe parameterised helpers (used only where explicitly noted) ──────────
    public async Task<int> ExecuteNonQueryParamAsync(string sql, Dictionary<string, object?> parameters)
    {
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        foreach (var kv in parameters)
            cmd.Parameters.AddWithValue(kv.Key, kv.Value ?? DBNull.Value);
        return await cmd.ExecuteNonQueryAsync();
    }
}
