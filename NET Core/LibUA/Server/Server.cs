
// Type: LibUA.Server.Master



using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace LibUA.Server
{
    public class Master
    {
        public readonly Application App = null;
        public readonly int MaximumMessageSize = 0;
        protected ILogger logger = null;
        private Socket listener = null;
        private Thread listenerThread = null;
        private ManualResetEvent listenerAccepted = null;
        private ManualResetEvent listenerAbort = null;
        private Semaphore listenerAvailable = null;
        private readonly List<NetDispatcherBase> dispatchers = null;
        private readonly object dispatchersLock = new object();
        protected int Port;
        protected int Timeout;
        protected int Backlog;
        protected int MaxClients;

        public Master(
          Application App,
          int Port,
          int Timeout,
          int Backlog,
          int MaxClients,
          ILogger logger,
          int MaximumMessageSize = 1048576)
        {
            this.App = App;
            this.logger = logger;
            this.Port = Port;
            this.Timeout = Timeout;
            this.Backlog = Backlog;
            this.MaxClients = MaxClients;
            this.MaximumMessageSize = MaximumMessageSize;
            this.dispatchers = new List<NetDispatcherBase>();
        }

        public void Start()
        {
            if (this.listener != null)
            {
                this.Stop();
            }

            this.listenerAccepted = new ManualResetEvent(false);
            this.listenerAbort = new ManualResetEvent(false);
            this.listenerAvailable = new Semaphore(this.MaxClients, this.MaxClients);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, this.Port);
            this.listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.listener.Bind(ipEndPoint);
            this.listener.Listen(this.Backlog);
            this.listenerThread = new Thread(new ParameterizedThreadStart(Master.ListenerThreadTarget));
            this.listenerThread.Start(this);
        }

        public void Stop()
        {
            if (this.listener != null)
            {
                this.listenerAbort.Set();
                this.listenerAccepted.Set();
                this.listener.Dispose();
                this.listener = null;
            }
            if (this.listenerThread != null)
            {
                this.listenerThread.Join();
            }

            while (this.dispatchers.Count > 0)
            {
                this.dispatchers[0].Close();
            }

            this.dispatchers.Clear();
        }

        protected static void ListenerThreadTarget(object args)
        {
            (args as Master).ListenerThreadTarget();
        }

        protected void ListenerThreadTarget()
        {
            while (!this.listenerAbort.WaitOne(0))
            {
                if (this.listenerAvailable.WaitOne(100))
                {
                    this.listenerAccepted.Reset();
                    this.listener.BeginAccept(new AsyncCallback(Master.AcceptCallback), this);
                    this.listenerAccepted.WaitOne();
                }
            }
        }

        protected static void AcceptCallback(IAsyncResult ar)
        {
            (ar.AsyncState as Master).Accept(ar);
        }

        protected void Accept(IAsyncResult ar)
        {
            if (this.listener == null)
            {
                return;
            }

            try
            {
                Socket socket = this.listener.EndAccept(ar);
                if (socket != null)
                {
                    socket.LingerState = new LingerOption(true, this.Timeout);
                    socket.NoDelay = true;
                    Monitor.Enter(this.dispatchersLock);
                    try
                    {
                        this.dispatchers.Add(new NetDispatcher(this, this.App, socket, this.logger));
                    }
                    finally
                    {
                        Monitor.Exit(this.dispatchersLock);
                    }
                }
                else
                {
                    this.listenerAvailable.Release();
                }

                this.listenerAccepted.Set();
            }
            catch
            {
                this.listenerAvailable.Release();
                this.listenerAccepted.Set();
            }
        }

        internal void RemoveDispatcher(NetDispatcherBase netDispatcher)
        {
            Monitor.Enter(this.dispatchersLock);
            try
            {
                if (!this.dispatchers.Contains(netDispatcher))
                {
                    return;
                }

                this.dispatchers.Remove(netDispatcher);
                this.listenerAvailable.Release();
            }
            finally
            {
                Monitor.Exit(this.dispatchersLock);
            }
        }
    }
}
