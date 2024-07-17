using LibUA.Core;

namespace LibUA.Tests
{
    [Collection(nameof(TestServerFixture))]
    public class TestServerClient : IDisposable
    {
        readonly TestClient client;

        public TestServerClient()
        {
            client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);

            Assert.Equal(StatusCode.Good, client.Connect());
            Assert.Equal(StatusCode.Good, client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null));
        }

        public void Dispose()
        {
            Assert.Equal(StatusCode.Good, client.Disconnect());

            client?.Dispose();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public void TestServerClient_ValidateApplicationDescriptions()
        {
            Assert.Equal(StatusCode.Good, client.FindServers(out ApplicationDescription[] appDescs, null));
            Assert.NotEmpty(appDescs);
        }

        [Fact]
        public void TestServerClient_ValidateUnfilteredEndpointDescriptions()
        {
            Assert.Equal(StatusCode.Good, client.GetEndpoints(out EndpointDescription[] endpointDescs, null));
            Assert.NotEmpty(endpointDescs);
        }
    }
}
