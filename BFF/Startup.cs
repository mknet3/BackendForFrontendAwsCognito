using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.SpaServices.ReactDevelopmentServer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;

namespace BackendForFrontend
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Strict;
                o.Cookie.HttpOnly = true;
            })
            .AddOpenIdConnect("AWSCognito", ConfigureOpenIdConnect);

            services.AddControllersWithViews();

            // In production, the React files will be served from this directory
            services.AddSpaStaticFiles(configuration =>
            {
                configuration.RootPath = "ClientApp/build";
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSpaStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller}/{action=Index}/{id?}");
            });

            app.UseSpa(spa =>
            {
                spa.Options.SourcePath = "ClientApp";

                if (env.IsDevelopment())
                {
                    spa.UseReactDevelopmentServer(npmScript: "start");
                }
            });
        }

        private void ConfigureOpenIdConnect(OpenIdConnectOptions options)
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.ClaimActions.Clear();

            options.TokenValidationParameters.NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

            options.ResponseType = "code";
            options.MetadataAddress = Configuration["AWSCognito:MetadataAddress"];

            options.ClientId = Configuration["AWSCognito:ClientId"];
            options.ClientSecret = Configuration["AWSCognito:ClientSecret"];

            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;

            options.Scope.Add("email");
            options.Scope.Add("profile");
            options.Scope.Add("openid");
            
            options.CallbackPath = new PathString("/callback");

            options.Events = new OpenIdConnectEvents
            {
                // handle the logout redirection
                OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    var logoutUri =
                        $"{Configuration["AWSCognito:LogoutUrl"]}?client_id={Configuration["AWSCognito:ClientId"]}";

                    var postLogoutUri = context.Properties.RedirectUri;
                    if (!string.IsNullOrEmpty(postLogoutUri))
                    {
                        if (postLogoutUri.StartsWith("/"))
                        {
                            // transform to absolute
                            var request = context.Request;
                            postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                        }

                        logoutUri += $"&logout_uri={Uri.EscapeDataString(postLogoutUri)}";
                    }

                    context.Response.Redirect(logoutUri);
                    context.HandleResponse();

                    return Task.CompletedTask;
                }
            };
        }
    }
}
