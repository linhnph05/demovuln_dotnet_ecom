using MySqlConnector;

namespace WebApplication1.Data;


public class DbHelper
{
    private readonly string _connectionString;

    public DbHelper(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection")!;
    }

    public MySqlConnection GetConnection() => new(_connectionString);

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

    public async Task<long> ExecuteInsertAsync(string sql)
    {
        await using var conn = GetConnection();
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
        return cmd.LastInsertedId;
    }

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
