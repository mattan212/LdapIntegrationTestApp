using System;
using System.Configuration;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using IntegrationsTestApp.Providers;
using IntegrationsTestApp.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.ActiveDirectory;

namespace IntegrationsTestApp
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public static string PublicClientId { get; private set; }

        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context and user manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Configure the application for OAuth based flow
            PublicClientId = "self";
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                Provider = new ApplicationOAuthProvider(PublicClientId),
                AuthorizeEndpointPath = new PathString("/api/Account/ExternalLogin"),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                // In production mode set AllowInsecureHttp = false
                AllowInsecureHttp = true
            };

            // Enable the application to use bearer tokens to authenticate users
            app.UseOAuthBearerTokens(OAuthOptions);
            
            //AD FS Authentication
            var abortCertificateValidation = bool.Parse(ConfigurationManager.AppSettings["AbortCertificateValidation"]);

            if (abortCertificateValidation)
            {
                ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateCertificate);
            }

            var adfsMetadataEndpoint = ConfigurationManager.AppSettings["AdfsMetadataEndpoint"];

            var adfsAudience = ConfigurationManager.AppSettings["AdfsAudience"];

            app.UseActiveDirectoryFederationServicesBearerAuthentication(
                new ActiveDirectoryFederationServicesBearerAuthenticationOptions
                {
                    MetadataEndpoint = adfsMetadataEndpoint,
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidAudience = adfsAudience
                    }
                });
        }

        static bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }
    }
}
