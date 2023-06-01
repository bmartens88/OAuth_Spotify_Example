using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OAuthRefresh;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<TokenDbContext>(opt =>
    opt.UseSqlite("Data Source = tokens.sqlite"));

builder.Services.AddHttpClient();

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", o =>
    {
        o.LoginPath = "/login";

        var del = o.Events.OnRedirectToAccessDenied;
        o.Events.OnRedirectToAccessDenied = ctx =>
        {
            if (ctx.Request.Path.StartsWithSegments("/spotify"))
                return ctx.HttpContext.ChallengeAsync("spotify");
            return del(ctx);
        };
    })
    .AddOAuth("spotify", o =>
    {
        o.SignInScheme = "cookie";
        o.CallbackPath = SpotifyConstants.CallbackPath;
        o.ClientId = SpotifyConstants.ClientId;
        o.ClientSecret = SpotifyConstants.ClientSecret;

        o.AuthorizationEndpoint = SpotifyConstants.AuthorizationEndpoint;
        o.TokenEndpoint = SpotifyConstants.TokenEndpoint;
        o.UserInformationEndpoint = SpotifyConstants.UserInfoEndpoint;

        o.SaveTokens = false;

        o.Events.OnCreatingTicket = async ctx =>
        {
            var db = ctx.HttpContext.RequestServices.GetRequiredService<TokenDbContext>();

            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);

            var authenticationHandlerProvider =
                ctx.HttpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            var handler = await authenticationHandlerProvider.GetHandlerAsync(ctx.HttpContext, "cookie");
            var authResult = await handler!.AuthenticateAsync();
            if (!authResult.Succeeded)
            {
                ctx.Fail("Failed authentication!");
                return;
            }

            var result = await ctx.Backchannel.SendAsync(request, ctx.HttpContext.RequestAborted);
            if (!result.IsSuccessStatusCode)
            {
                ctx.Fail("Failed Authentication!");
                return;
            }

            using var content = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
            var user = content.RootElement;
            var userId = user.GetProperty("id").GetString()!;

            var storedInfo = await db.TokenInfo.FirstOrDefaultAsync(ti => ti.UserId == userId);
            if (storedInfo is null)
            {
                storedInfo = new TokenInfo
                {
                    UserId = userId,
                    AccessToken = ctx.AccessToken,
                    RefreshToken = ctx.RefreshToken,
                    Expires = DateTime.UtcNow.AddSeconds(int.Parse(ctx.TokenResponse.ExpiresIn))
                };
                await db.TokenInfo.AddAsync(storedInfo);
            }
            else
            {
                storedInfo.AccessToken = ctx.AccessToken;
                storedInfo.RefreshToken = ctx.RefreshToken;
                storedInfo.Expires = DateTime.UtcNow.AddSeconds(int.Parse(ctx.TokenResponse.ExpiresIn));
            }

            await db.SaveChangesAsync();

            ctx.Identity?.AddClaim(new Claim("spotify-id", userId));
        };
    });

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("spotify-enabled", pb =>
    {
        pb.AddAuthenticationSchemes("spotify")
            .RequireAuthenticatedUser()
            .RequireClaim("spotify-id");
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) => { return ctx.User.Claims.Select(x => new { x.Type, x.Value }).ToList(); });

app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, new[] { "spotify" }));

app.MapGet("/spotify/info",
        async (
            HttpContext ctx,
            TokenDbContext db,
            HttpClient client) =>
        {
            var userId = ctx.User.FindFirstValue("spotify-id");
            var tokenInfo = await db.TokenInfo.FirstOrDefaultAsync(i => i.UserId == userId);
            if (tokenInfo is null)
                return Results.BadRequest("No token for this user?!");
            var request = new HttpRequestMessage(HttpMethod.Get, SpotifyConstants.UserInfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenInfo.AccessToken);
            var result = await client.SendAsync(request);
            return !result.IsSuccessStatusCode
                ? Results.BadRequest("Failed to send HTTP request")
                : Results.Ok(await result.Content.ReadAsStringAsync());
        })
    .RequireAuthorization("spotify-enabled");

app.MapGet("/refresh", async (
        HttpContext ctx,
        TokenDbContext db,
        HttpClient client) =>
    {
        var userId = ctx.User.FindFirstValue("spotify-id");
        var tokenInfo = await db.TokenInfo.FirstOrDefaultAsync(i => i.UserId == userId);
        if (tokenInfo is null)
            return Results.BadRequest("No token for this user?!");
        var requestParams = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"refresh_token", tokenInfo.RefreshToken},
            {"client_id", SpotifyConstants.ClientId}
        };
        var requestContent = new FormUrlEncodedContent(requestParams);
        var request = new HttpRequestMessage(HttpMethod.Post, SpotifyConstants.TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = requestContent;
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{SpotifyConstants.ClientId}:{SpotifyConstants.ClientSecret}")));
        var response = await client.SendAsync(request);
        if (!response.IsSuccessStatusCode)
            return Results.BadRequest("Error while sending HTTP request");
        var accessToken = (await response.Content.ReadFromJsonAsync<OAuthRefreshResponse>())!.access_token;
        tokenInfo.AccessToken = accessToken;
        tokenInfo.Expires=DateTime.UtcNow.AddSeconds(3600);
        await db.SaveChangesAsync();
        return Results.Ok();
    })
    .RequireAuthorization("spotify-enabled");

app.Run();

public sealed class TokenDbContext : DbContext
{
    public TokenDbContext(
        DbContextOptions<TokenDbContext> options) :
        base(options)
    {
    }

    public DbSet<TokenInfo> TokenInfo => Set<TokenInfo>();
}

public class TokenInfo
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime Expires { get; set; }
}

public class OAuthRefreshResponse
{
    public string access_token { get; set; }
}