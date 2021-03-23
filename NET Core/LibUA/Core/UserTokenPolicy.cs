
// Type: LibUA.Core.UserTokenPolicy



namespace LibUA.Core
{
    public class UserTokenPolicy
    {
        public string PolicyId { get; protected set; }

        public UserTokenType TokenType { get; protected set; }

        public string IssuedTokenType { get; protected set; }

        public string IssuerEndpointUrl { get; protected set; }

        public string SecurityPolicyUri { get; protected set; }

        public UserTokenPolicy(
          string PolicyId,
          UserTokenType TokenType,
          string IssuedTokenType,
          string IssuerEndpointUrl,
          string SecurityPolicyUri)
        {
            this.PolicyId = PolicyId;
            this.TokenType = TokenType;
            this.IssuedTokenType = IssuedTokenType;
            this.IssuerEndpointUrl = IssuerEndpointUrl;
            this.SecurityPolicyUri = SecurityPolicyUri;
        }
    }
}
