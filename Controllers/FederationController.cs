using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using IntegrationsTestApp.Models;

namespace IntegrationsTestApp.Controllers
{
    [RoutePrefix("api/Federation")]
    public class FederationController : ApiController
    {
        [Route("Authenticate")]
        [HttpGet]
        public IHttpActionResult Authenticate(string username, string password)
        {
            var stsEndpoint = ConfigurationManager.AppSettings["StsEndpoint"];

            var relyingPartyAddress = ConfigurationManager.AppSettings["AdfsAudience"];

            var tokenFactory = new AuthenticationTokenFactory();

            try
            {
                var token = tokenFactory.AuthenticateUser(username, password, stsEndpoint, relyingPartyAddress);

                return Ok(token);
            }
            catch (Exception e)
            {
                return BadRequest("Authentication failed. Exception Message: " + e.Message);
            }
        }

        [Route("GetClaims")]
        [HttpGet]
        public IHttpActionResult GetClaims()
        {
            var res = ((ClaimsPrincipal) User).Claims.Select(x => new KeyValuePair<string, string>(x.Type, x.Value));

            return Ok(res);
        }
    }
}
