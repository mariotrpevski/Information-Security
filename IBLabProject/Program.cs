using IBLabProject;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddSingleton<EmailSender>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
        options.AccessDeniedPath = "/access-denied.html";
    });
builder.Services.AddAuthorization();
builder.Services.AddSession();

var app = builder.Build();

// ----------------- Default page -----------------
var options = new DefaultFilesOptions();
options.DefaultFileNames.Clear();
options.DefaultFileNames.Add("login.html");
app.UseDefaultFiles(options);   
app.UseStaticFiles();

// ----------------- Middleware -----------------
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

string usersFile = "users.json";

// Ensure users.json exists
if (!File.Exists(usersFile))
{
    File.WriteAllText(usersFile, "[]");
}

#region Helper Methods

List<User> LoadUsers()
{
    var json = File.ReadAllText(usersFile);
    return JsonSerializer.Deserialize<List<User>>(json) ?? new List<User>();
}

void SaveUsers(List<User> users)
{
    var json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(usersFile, json);
}

#endregion

// ---------------- REGISTER ----------------
app.MapPost("/register", async (HttpContext ctx, EmailSender emailSender) =>
{
    var form = await ctx.Request.ReadFromJsonAsync<RegisterRequest>();
    if (form == null)
        return Results.BadRequest("Invalid data");

    // ---------------- Validation ----------------
    var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
    if (!emailRegex.IsMatch(form.Email))
        return Results.BadRequest("Invalid email format");

    var passwordRegex = new Regex(@"^(?=.*[A-Z])(?=.*[!@#$%^&*(),.?""{}|<>]).{8,}$");
    if (!passwordRegex.IsMatch(form.Password))
        return Results.BadRequest("Password must be at least 8 characters, contain 1 uppercase letter and 1 symbol");

    var users = LoadUsers();
    if (users.Any(u => u.Email == form.Email))
        return Results.BadRequest("User already exists");

    var code = Random.Shared.Next(100000, 999999).ToString();

    ctx.Session.SetString("pending_user", JsonSerializer.Serialize(form));
    ctx.Session.SetString("verification_code", code);

    await emailSender.SendVerificationCodeAsync(form.Email, form.Username, code);

    return Results.Ok("Verification code sent");
});


// ---------------- CONFIRM EMAIL ----------------
app.MapPost("/confirm", (HttpContext ctx) =>
{
    var inputCode = ctx.Request.Form["code"].ToString();
    var storedCode = ctx.Session.GetString("verification_code");
    var pendingUserJson = ctx.Session.GetString("pending_user");

    if (storedCode != inputCode || pendingUserJson == null)
        return Results.BadRequest("Invalid code");

    var pendingUser = JsonSerializer.Deserialize<RegisterRequest>(pendingUserJson)!;
    var users = LoadUsers();

    var role = pendingUser.Username == "MAdmin" ? "Admin" : "User";

    users.Add(new User
    {
        Email = pendingUser.Email,
        Username = pendingUser.Username,
        PasswordHash = PasswordHasher.Hash(pendingUser.Password),
        Role = role,
        RequestsApproved = false
    });


    SaveUsers(users);

    ctx.Session.Clear();
    return Results.Redirect("/login.html");
});

// ---------------- LOGIN ----------------
app.MapPost("/login", async (HttpContext ctx, EmailSender emailSender) =>
{
    var form = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
    var users = LoadUsers();

    var user = users.FirstOrDefault(u => u.Email == form!.Email);
    if (user == null || !PasswordHasher.Verify(form.Password, user.PasswordHash))
        return Results.BadRequest("Invalid credentials");

    var code = Random.Shared.Next(100000, 999999).ToString();
    ctx.Session.SetString("2fa_user", user.Email);
    ctx.Session.SetString("2fa_code", code);

    await emailSender.SendVerificationCodeAsync(user.Email, user.Username, code);

    return Results.Ok("2FA code sent");
});

// ---------------- VERIFY 2FA ----------------
app.MapPost("/verify-2fa", async (HttpContext ctx) =>
{
    var codeInput = ctx.Request.Form["code"].ToString();
    var storedCode = ctx.Session.GetString("2fa_code");
    var email = ctx.Session.GetString("2fa_user");

    if (storedCode != codeInput || email == null)
        return Results.BadRequest("Invalid code");

    var users = LoadUsers();
    var user = users.First(u => u.Email == email);
    var role = user.Username == "MAdmin" ? "Admin" : "User";

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    ctx.Session.Remove("2fa_code");
    ctx.Session.Remove("2fa_user");

    return Results.Redirect("/welcome.html");
});

// ---------------- LOGOUT ----------------
app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.Ok("Logged out");
});

// ---------------- CURRENT USER ----------------
app.MapGet("/me", [Authorize] (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Username = user.Identity!.Name,
        Role = user.FindFirst(ClaimTypes.Role)?.Value
    });
});

// ---------------- ADMIN DASHBOARD ----------------
app.MapGet("/admin/dashboard", [Authorize(Roles = "Admin")] () =>
{
    var users = LoadUsers();

    var regularUsers = users
        .Where(u => u.Username != "MAdmin")
        .ToList();

    return Results.Ok(regularUsers);
});


// ---------------- USER REQUEST ----------------
app.MapPost("/user/request-info", [Authorize] (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;
    var users = LoadUsers();
    var user = users.First(u => u.Username == username);

    user.RequestsApproved = false;
    SaveUsers(users);

    return Results.Ok("Request sent");
});

// ---------------- ADMIN APPROVE/DENY ----------------
app.MapPost("/admin/approve/{username}", [Authorize(Roles = "Admin")] (string username) =>
{
    var users = LoadUsers();
    var user = users.First(u => u.Username == username);

    user.RequestsApproved = true;
    SaveUsers(users);

    return Results.Ok("Approved");
});

app.MapPost("/admin/deny/{username}", [Authorize(Roles = "Admin")] (string username) =>
{
    var users = LoadUsers();
    var user = users.First(u => u.Username == username);

    user.RequestsApproved = false;
    SaveUsers(users);

    return Results.Ok("Denied");
});


// ---------------- DOWNLOAD INFO ----------------
app.MapGet("/user/download-info", [Authorize] (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;
    var users = LoadUsers();
    var user = users.First(u => u.Username == username);

    // Allow admin to bypass request approval
    if (user.Username != "MAdmin" && !user.RequestsApproved)
        return Results.BadRequest("Not approved");

    var content = $"Username: {user.Username}\nEmail: {user.Email}\nRole: {user.Role}";
    return Results.File(
        System.Text.Encoding.UTF8.GetBytes(content),
        "text/plain",
        "userinfo.txt");
});

// Check request status for current user
app.MapGet("/user/request-status", [Authorize] (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;
    var users = LoadUsers();
    var user = users.First(u => u.Username == username);

    // Return status and remaining time (if approved)
    if (user.RequestsApproved)
    {
        // Track approval time in session
        var approvalTimeStr = ctx.Session.GetString($"approval_time_{username}");
        DateTime approvalTime;

        if (string.IsNullOrEmpty(approvalTimeStr))
        {
            approvalTime = DateTime.UtcNow;
            ctx.Session.SetString($"approval_time_{username}", approvalTime.ToString("o")); // ISO 8601 UTC
        }
        else
        {
            approvalTime = DateTime.Parse(approvalTimeStr, null, System.Globalization.DateTimeStyles.AdjustToUniversal);
        }

        var elapsed = DateTime.UtcNow - approvalTime;
        var remaining = TimeSpan.FromMinutes(10) - elapsed;

        if (remaining.TotalSeconds <= 0)
        {
            // Time expired → reset
            user.RequestsApproved = false;
            SaveUsers(users);
            ctx.Session.Remove($"approval_time_{username}");
            return Results.Json(new { status = "Denied", remainingSeconds = 0 });
        }

        return Results.Json(new { status = "Approved", remainingSeconds = (int)Math.Ceiling(remaining.TotalSeconds) });
    }

    // Explicit return when not approved to satisfy all code paths
    return Results.Json(new { status = "Denied", remainingSeconds = 0 });
});


app.Run();


// ---------------- MODELS ----------------

public class User
{
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "User";
    public bool RequestsApproved { get; set; }
}

public class RegisterRequest
{
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class LoginRequest
{
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
}
