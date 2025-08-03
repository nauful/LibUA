namespace LibUA.Tests
{
    public class TestClientFixture : IDisposable
    {
        public TestClient client;

        public TestClientFixture()
        {
            client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
        }

        public void Dispose()
        {
            client?.Disconnect();
            client?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
