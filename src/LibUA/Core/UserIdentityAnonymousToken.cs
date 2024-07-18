namespace LibUA
{
    namespace Core
    {
        public class UserIdentityAnonymousToken
        {
            public string PolicyId { get; protected set; }
            public UserIdentityAnonymousToken(string PolicyId)
            {
                this.PolicyId = PolicyId;
            }
        }
    }
}
