using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Extensions.Logging;

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
            private Socket listener = null;
            private Thread listenerThread = null;
            private ManualResetEvent listenerAccepted = null;
            private ManualResetEvent listenerAbort = null;
            private Semaphore listenerAvailable = null;
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

                listenerAccepted = new ManualResetEvent(false);
                listenerAbort = new ManualResetEvent(false);
                listenerAvailable = new Semaphore(MaxClients, MaxClients);

                IPEndPoint localEndPoint = new IPEndPoint(LocalEndpoint, Port);

                listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(localEndPoint);
                listener.Listen(Backlog);

                listenerThread = new Thread(new ParameterizedThreadStart(ListenerThreadTarget));
                listenerThread.Start(this);
            }

            public void Stop()
            {
                if (listener != null)
                {
                    listenerAbort.Set();
                    listenerAccepted.Set();

                    listener.Dispose();
                    listener = null;
                }

                listenerThread?.Join();

                while (dispatchers.Count > 0)
                {
                    var disp = dispatchers[0];
                    disp.Close();
                }

                dispatchers.Clear();
            }

            protected static void ListenerThreadTarget(object args)
            {
                (args as Master).ListenerThreadTarget();
            }

            protected void ListenerThreadTarget()
            {
                while (!listenerAbort.WaitOne(0))
                {
                    if (!listenerAvailable.WaitOne(100))
                    {
                        continue;
                    }

                    listenerAccepted.Reset();
                    listener.BeginAccept(new AsyncCallback(AcceptCallback), this);
                    listenerAccepted.WaitOne();
                }
            }

            protected static void AcceptCallback(IAsyncResult ar)
            {
                (ar.AsyncState as Master).Accept(ar);
            }

            protected void Accept(IAsyncResult ar)
            {
                if (listener == null)
                {
                    return;
                }

                try
                {
                    var handler = listener.EndAccept(ar);

                    if (handler != null)
                    {
                        handler.NoDelay = true;

                        Monitor.Enter(dispatchersLock);
                        try
                        {
                            dispatchers.Add(new NetDispatcher(this, App, handler, logger));
                        }
                        finally
                        {
                            Monitor.Exit(dispatchersLock);
                        }
                    }
                    else
                    {
                        listenerAvailable.Release();
                    }

                    listenerAccepted.Set();
                }
                catch
                {
                    // Listener closed

                    listenerAvailable.Release();
                    listenerAccepted.Set();
                }
            }

            internal void RemoveDispatcher(NetDispatcherBase netDispatcher)
            {
                Monitor.Enter(dispatchersLock);
                try
                {
                    if (dispatchers.Contains(netDispatcher))
                    {
                        dispatchers.Remove(netDispatcher);
                        listenerAvailable.Release();
                    }
                }
                finally
                {
                    Monitor.Exit(dispatchersLock);
                }
            }
        }
    }
}
