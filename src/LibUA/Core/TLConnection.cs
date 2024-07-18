namespace LibUA
{
    namespace Core
    {
        public class TLConnection
        {
            public TLConfiguration LocalConfig { get; set; }
            public TLConfiguration RemoteConfig { get; set; }

            public string RemoteEndpoint { get; set; }
        }
    }
}
