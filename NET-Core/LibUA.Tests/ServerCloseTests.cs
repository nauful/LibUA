using System.Net;
using System.Net.Sockets;
using LibUA.Server;
using Microsoft.Extensions.Logging.Abstractions;

namespace LibUA.Tests
{
    /// <summary>
    /// Regression tests for issue #259: closing a server with a connected
    /// client used to throw ObjectDisposedException in
    /// NetDispatcherBase.ThreadTarget(). Close() disposed the socket before
    /// thread.Join(), racing with the dispatcher thread's own teardown.
    ///
    /// An unhandled exception on the dispatcher thread terminates the whole
    /// test host process, so "the test completes at all" is the pass signal.
    /// </summary>
    public class ServerCloseTests
    {
        // Time for the dispatcher thread to accept the connection and enter
        // its Socket.Select loop
        private const int ConnectSettleMs = 500;

        [Fact]
        public void Stop_WithIdleConnectedClient_DoesNotCrash()
        {
            int port = ReserveFreePort();
            var master = new Master(new Application(), port, 10, 30, 100, NullLogger.Instance);
            master.Start();

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(IPAddress.Loopback, port);

            Thread.Sleep(ConnectSettleMs);

            // The dispatcher owns its socket teardown; Close() must only
            // signal and join the thread
            master.Stop();
        }

        [Fact]
        public void Stop_WithMultipleConnectedClients_IsBounded()
        {
            int port = ReserveFreePort();
            var master = new Master(new Application(), port, 10, 30, 100, NullLogger.Instance);
            master.Start();

            var clients = new List<Socket>();
            for (int i = 0; i < 5; i++)
            {
                var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                client.Connect(IPAddress.Loopback, port);
                clients.Add(client);
            }

            Thread.Sleep(ConnectSettleMs);

            // Run Stop() on a task so a hung join becomes a test failure
            // instead of an indefinite hang
            var stopTask = Task.Run(master.Stop);
            Assert.True(stopTask.Wait(TimeSpan.FromSeconds(30)),
                "Master.Stop() did not return in bounded time");

            clients.ForEach(c => c.Dispose());
        }

        private static int ReserveFreePort()
        {
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            int port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }
    }
}