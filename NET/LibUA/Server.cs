using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using LibUA.Core;

namespace LibUA
{
    namespace Server
    {
        public class Master
        {
            public readonly Application App = null;
            public readonly int MaximumMessageSize = 0;

            protected int Port, Timeout, Backlog, MaxClients;
            protected ILogger logger = null;
            private TcpListener listener = null;
            private Thread listenerThread = null;
            private readonly List<NetDispatcherBase> dispatchers = null;
            private readonly object dispatchersLock = new object();

            public Master(Application App, int Port, int Timeout, int Backlog, int MaxClients, ILogger logger, int MaximumMessageSize = 1 << 20)
            {
                this.App = App;
                this.logger = logger;

                this.Port = Port;
                this.Timeout = Timeout;
                this.Backlog = Backlog;
                this.MaxClients = MaxClients;
                this.MaximumMessageSize = MaximumMessageSize;

                dispatchers = new List<NetDispatcherBase>();
            }

            public void Start()
            {
                Start(IPAddress.Any);
            }

            public void Start(IPAddress LocalEndpoint)
            {
                if (listener != null)
                {
                    Stop();
                }

                IPEndPoint localEndPoint = new IPEndPoint(LocalEndpoint, Port);

                listener = new TcpListener(localEndPoint);
                listener.Start(Backlog);

                listenerThread = new Thread(new ParameterizedThreadStart(ListenerThreadTarget));
                listenerThread.Name = $"Listener Thread : {localEndPoint}";
                listenerThread.Start(this);
            }

            public void Stop()
            {
                listener?.Stop();
                listener = null;

                listenerThread?.Join();

                while (dispatchers.Count > 0)
                {
                    var disp = dispatchers[0];
                    disp.Close();
                }

                dispatchers.Clear();
            }

            protected static async void ListenerThreadTarget(object args)
            {
                await (args as Master).ListenerThreadTarget();
            }

            protected async Task ListenerThreadTarget()
            {
                while (true)
                {
                    var client = await listener.AcceptSocketAsync();
                    if (dispatchers.Count >= MaxClients)
                    {
                        client?.Close();
                        continue;
                    }
                    client.NoDelay = true;
                    var clientStream = new NetworkStreamWithSocket(client, true);
                    lock (dispatchersLock)
                    {
                        dispatchers.Add(new NetDispatcher(this, App, clientStream, logger));
                    }

                }
            }
            internal void RemoveDispatcher(NetDispatcherBase netDispatcher)
            {
                lock (dispatchersLock)
                {
                    dispatchers.Remove(netDispatcher);
                }
            }
        }

        public class ContinuationPointBrowse
        {
            public bool IsValid;
            public int Offset, MaxReferencesPerNode;
            public BrowseDescription Desc { get; protected set; }
            public ContinuationPointBrowse(BrowseDescription Desc, int MaxReferencesPerNode)
            {
                this.Desc = Desc;
                this.MaxReferencesPerNode = MaxReferencesPerNode;

                IsValid = false;
                Offset = 0;
            }
        }

        public class ContinuationPointHistory
        {
            public bool IsValid;
            public int Offset;
            public object Details;
            public TimestampsToReturn ReturnTimes;
            public HistoryReadValueId ReadId;

            public ContinuationPointHistory(object Details, TimestampsToReturn ReturnTimes, HistoryReadValueId ReadId)
            {
                this.Details = Details;
                this.ReturnTimes = ReturnTimes;
                this.ReadId = ReadId;

                IsValid = false;
                Offset = 0;
            }
        }
    }
}
