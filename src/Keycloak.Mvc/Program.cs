using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Keycloak.AuthServices.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Keycloak.Mvc;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // https://nikiforovall.github.io/keycloak-authorization-services-dotnet/
        builder
            .Services
            .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            .AddKeycloakWebApp(
                builder.Configuration.GetSection(KeycloakAuthenticationOptions.Section),
                configureOpenIdConnectOptions: opt =>
                {
                    opt.SaveTokens = true;
                    opt.ResponseType = OpenIdConnectResponseType.Code;
                    opt.GetClaimsFromUserInfoEndpoint = true;
                    opt.MapInboundClaims = false;
                    opt.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
                    opt.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;
                    opt.Events = new OpenIdConnectEvents
                    {
                        OnSignedOutCallbackRedirect = context =>
                        {
                            context.Response.Redirect("/");
                            context.HandleResponse();
                            return Task.CompletedTask;
                        },
                        OnTokenResponseReceived = context =>
                        {
                            var identity = context?.Principal?.Identity as ClaimsIdentity;
                            identity?.AddClaims(new[]
                            {
                                //there is the "cat jump" or as we say in Brazil "o pulo do gato"
                                new Claim("access_token", context.TokenEndpointResponse.AccessToken),
                                new Claim("id_token", context.TokenEndpointResponse.IdToken)
                            });
                            context.Properties.IsPersistent = true;
                            context.Properties.ExpiresUtc =
                                new JwtSecurityToken(context.TokenEndpointResponse.AccessToken).ValidTo;
                            return Task.CompletedTask;
                        }
                    };
                },
                configureCookieAuthenticationOptions: opt =>
                {
                    opt.LogoutPath = "/acesso/sair";
                    opt.AccessDeniedPath = "/acesso/negado";
                });
        // Add services to the container.
        builder.Services.AddControllersWithViews();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        app.Run();
    }
}