namespace LibUA
{
    namespace Core
    {
        public class EndpointDescription
        {
            public string EndpointUrl
            {
                get; protected set;
            }

            public ApplicationDescription Server
            {
                get; protected set;
            }

            public byte[] ServerCertificate
            {
                get; protected set;
            }

            public MessageSecurityMode SecurityMode
            {
                get; protected set;
            }

            public string SecurityPolicyUri
            {
                get; protected set;
            }

            public UserTokenPolicy[] UserIdentityTokens
            {
                get; protected set;
            }

            public string TransportProfileUri
            {
                get; protected set;
            }

            public byte SecurityLevel
            {
                get; protected set;
            }

            public EndpointDescription(string EndpointUrl, ApplicationDescription Server, byte[] ServerCertificate, MessageSecurityMode SecurityMode, string SecurityPolicyUri, UserTokenPolicy[] UserIdentityTokens, string TransportProfileUri, byte SecurityLevel)
            {
                this.EndpointUrl = EndpointUrl;
                this.Server = Server;
                this.ServerCertificate = ServerCertificate;
                this.SecurityMode = SecurityMode;
                this.SecurityPolicyUri = SecurityPolicyUri;
                this.UserIdentityTokens = UserIdentityTokens;
                this.TransportProfileUri = TransportProfileUri;
                this.SecurityLevel = SecurityLevel;
            }
        }
    }
}
