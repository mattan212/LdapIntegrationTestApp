using System;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;
using WSTrustChannel = Microsoft.IdentityModel.Protocols.WSTrust.WSTrustChannel;
using WSTrustChannelFactory = Microsoft.IdentityModel.Protocols.WSTrust.WSTrustChannelFactory;
namespace IntegrationsTestApp.Models
{
    public class AuthenticationTokenFactory
    {
        public virtual string AuthenticateUser(string username, string password, string stsEndpoint, string relyingPartyAddress)
        {
            if (string.IsNullOrEmpty(stsEndpoint) || string.IsNullOrEmpty(relyingPartyAddress) ||
                string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                throw new NullReferenceException(
                    "AuthenticationTokenFactory received a null/empty argument for: username || password || stsEndpoint || relyingPartyAddress ");
            }

            var binding = new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential)
            {
                ClientCredentialType = HttpClientCredentialType.None
            };

            var trustChannelFactory = new WSTrustChannelFactory(binding, new EndpointAddress(stsEndpoint))
            {
                TrustVersion = TrustVersion.WSTrust13
            };

            var channelCredentials = trustChannelFactory.Credentials;
            channelCredentials.UserName.UserName = username;
            channelCredentials.UserName.Password = password;
            channelCredentials.SupportInteractive = false;

            var tokenClient = (WSTrustChannel)trustChannelFactory.CreateChannel();

            var rst = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue, WSTrust13Constants.KeyTypes.Bearer)
            {
                AppliesTo = new System.ServiceModel.EndpointAddress(relyingPartyAddress),
                ReplyTo = relyingPartyAddress,
                TokenType = "urn:ietf:params:oauth:token-type:jwt"
            };

            var token = tokenClient.Issue(rst);

            var innerXml = ((GenericXmlSecurityToken)token).TokenXml.InnerXml;

            byte[] data = Convert.FromBase64String(innerXml);

            string decodedString = Encoding.UTF8.GetString(data);

            return decodedString;
        }
    }
}
