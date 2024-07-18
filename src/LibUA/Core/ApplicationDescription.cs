namespace LibUA
{
    namespace Core
    {
        public class ApplicationDescription
        {
            public string ApplicationUri
            {
                get; protected set;
            }

            public string ProductUri
            {
                get; protected set;
            }

            public LocalizedText ApplicationName
            {
                get; protected set;
            }

            public ApplicationType Type
            {
                get; protected set;
            }

            public string GatewayServerUri
            {
                get; protected set;
            }

            public string DiscoveryProfileUri
            {
                get; protected set;
            }

            public string[] DiscoveryUrls
            {
                get; protected set;
            }

            public ApplicationDescription(string ApplicationUri, string ProductUri, LocalizedText ApplicationName, ApplicationType Type, string GatewayServerUri, string DiscoveryProfileUri, string[] DiscoveryUrls)
            {
                this.ApplicationUri = ApplicationUri;
                this.ProductUri = ProductUri;
                this.ApplicationName = ApplicationName;
                this.Type = Type;
                this.GatewayServerUri = GatewayServerUri;
                this.DiscoveryProfileUri = DiscoveryProfileUri;
                this.DiscoveryUrls = DiscoveryUrls;
            }
        }
    }
}
