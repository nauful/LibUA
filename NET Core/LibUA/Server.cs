using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

			Socket listener = null;
			Thread listenerThread = null;

			ManualResetEvent listenerAccepted = null;
			ManualResetEvent listenerAbort = null;
			Semaphore listenerAvailable = null;

			List<NetDispatcherBase> dispatchers = null;
			object dispatchersLock = new object();

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
				if (listener != null)
				{
					Stop();
				}

				listenerAccepted = new ManualResetEvent(false);
				listenerAbort = new ManualResetEvent(false);
				listenerAvailable = new Semaphore(MaxClients, MaxClients);

				IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, Port);

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

				if (listenerThread != null)
				{
					listenerThread.Join();
				}

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
						handler.LingerState = new LingerOption(true, Timeout);
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

		public class NetDispatcherBase
		{
			public const int MaxContinuationPoints = 256;
			public const int MaxPublishRequests = 1024;
			public const int MaxMonitoredPerSubscription = 65536;
			public const int MaxTokenLifetime = 600 * 1000;
			public const uint MaxBrowseResults = 10000;
			public const uint MaxHistoryReadNodes = 256;
			public const uint MaxSubscriptionAcknowledgementsPerPublish = 16;

			// Message type, message size, secure channel ID, security token ID
			public const int MessageEncodedBlockStart = 16;
			public const int ChunkHeaderOverhead = 4 * 6;

			public const double UsableMessageSizeFactor = 0.8;
			public const int TLPaddingOverhead = 1024;

			uint uaStatusCode = 0;
			public uint UAStatusCode
			{
				get { return uaStatusCode; }
				protected set { uaStatusCode = value; }
			}

			protected const int ErrorInternal = -1;
			protected const int ErrorParseFail = -2;
			protected const int ErrorRespWrite = -3;
			protected const int ErrorClosed = -4;

			public const int PulseInterval = 100;

			protected Application app = null;
			protected ILogger logger = null;
			Master server = null;
			protected Socket socket = null;
			protected int maximumMessageSize;

			// Ensure publishes are in sequence and not in parallel
			object csDispatching = new object();

			protected Thread thread = null;
			protected bool threadAbort = false;

			protected SLChannel config = null;

			protected UInt32 nextSubscriptionID = 1;
			protected Queue<RequestHeader> pendingNotificationRequests = null;
			protected Dictionary<uint, Queue<uint>> pendingSubscriptionAcknowledgements = null;
			//protected Dictionary<uint, Application.MonitorDispatcherConfiguration> monitorMap = null;
			//protected List<Application.MonitorDispatcherConfiguration> monitorList = null;

			protected Dictionary<UInt32, Subscription> subscriptionMap = null;

			protected Stack<int> availableContinuationPoints = null;
			protected Dictionary<int, ContinuationPointBrowse> continuationBrowse = null;
			protected Dictionary<int, ContinuationPointHistory> continuationHistory = null;

			public NetDispatcherBase(Master server, Application app, Socket socket, ILogger logger)
			{
				this.app = app;
				this.logger = logger;
				this.server = server;
				this.socket = socket;
				this.maximumMessageSize = server.MaximumMessageSize;

				this.UAStatusCode = (uint)StatusCode.Good;

				availableContinuationPoints = new Stack<int>();
				for (int i = MaxContinuationPoints - 1; i >= 0; i--)
				{
					availableContinuationPoints.Push(1 + i);
				}
				continuationBrowse = new Dictionary<int, ContinuationPointBrowse>();
				continuationHistory = new Dictionary<int, ContinuationPointHistory>();

				pendingNotificationRequests = new Queue<RequestHeader>();
				pendingSubscriptionAcknowledgements = new Dictionary<uint, Queue<uint>>();
				//monitorMap = new Dictionary<uint, Application.MonitorDispatcherConfiguration>();
				//monitorList = new List<Application.MonitorDispatcherConfiguration>();

				subscriptionMap = new Dictionary<uint, Subscription>();

				thread = new Thread(new ParameterizedThreadStart(ThreadTarget));
			}

			protected static void ThreadTarget(object args)
			{
				(args as NetDispatcherBase).ThreadTarget();
			}

			// Skip MessageType and ChunkType, write MessageSize
			protected void MarkPositionAsSize(MemoryBuffer mb)
			{
				UInt32 pos = (UInt32)mb.Position;
				mb.Position = 4;
				mb.Encode(pos);
				mb.Position = (int)pos;
			}

			protected void MarkPositionAsSize(MemoryBuffer mb, UInt32 position)
			{
				int restorePos = mb.Position;
				mb.Position = 4;
				mb.Encode(position);
				mb.Position = restorePos;
			}

			private void TLError(uint statusCode)
			{
				var respBuf = new MemoryBuffer(1 << 10);
				bool succeeded = true;
				succeeded &= respBuf.Encode((uint)(MessageType.Error) | ((uint)'F' << 24));
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode((UInt32)statusCode);
				succeeded &= respBuf.EncodeUAString(string.Format("TL error 0x{0}", statusCode.ToString("X")));

				if (succeeded)
				{
					MarkPositionAsSize(respBuf);
					socket.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
				}

				if (logger != null) { logger.Log(LogLevel.Error, string.Format("Sent TL error 0x{0}", statusCode.ToString("X"))); }
			}

			private void ThreadTarget()
			{
				var sessionInfo = new Application.SessionCreationInfo()
				{
					Endpoint = socket.RemoteEndPoint
				};

				if (logger != null) { logger.Log(LogLevel.Info, string.Format("Accepted connection from {0}", sessionInfo.Endpoint)); }

				config = new SLChannel();
				config.Endpoint = socket.RemoteEndPoint as IPEndPoint;
				config.Session = app.SessionCreate(sessionInfo);
				config.SLState = ConnectionState.Opening;

				int recvAccumSize = 0;
				var recvBuffer = new byte[maximumMessageSize];

				DateTime lastServerAliveNotification = DateTime.MinValue;

				while (socket.Connected)
				{
					if (threadAbort)
					{
						break;
					}

					while (NeedsPulse())
					{
						Monitor.Enter(csDispatching);

						try
						{
							//var sw = new System.Diagnostics.Stopwatch();
							//sw.Start();
							if (!Pulse())
							{
								if (logger != null) { logger.Log(LogLevel.Error, "Pulse failed"); }
								recvAccumSize = -1;
								break;
							}
							//sw.Stop();
							//Console.WriteLine("Pulse in {0}", sw.Elapsed.ToString());
						}
						finally
						{
							Monitor.Exit(csDispatching);
						}
					}

					if (!socket.Poll(PulseInterval * 1000, SelectMode.SelectRead))
					{
						continue;
					}

					int bytesRead = 0;
					int bytesAvailable = maximumMessageSize - recvAccumSize;
					if (bytesAvailable < 0)
					{
						break;
					}

					try
					{
						bytesRead = socket.Receive(recvBuffer, recvAccumSize, bytesAvailable, SocketFlags.None);
					}
					catch
					{
						break;
					}

					if (bytesRead == 0)
					{
						// Disconnected
						break;
					}

					recvAccumSize += bytesRead;
					if (recvAccumSize > maximumMessageSize)
					{
						if (logger != null) { logger.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", recvAccumSize, maximumMessageSize)); }
						break;
					}

					while (recvAccumSize > 0 && UAStatusCode == (uint)StatusCode.Good)
					{
						Monitor.Enter(csDispatching);
						int consumedSize = -1;

						try
						{
							consumedSize = Consume(new MemoryBuffer(recvBuffer, recvAccumSize));
						}
						catch (NotImplementedException)
						{
							if (UAStatusCode == (uint)StatusCode.Good) { UAStatusCode = (uint)StatusCode.BadNotImplemented; }
							consumedSize = ErrorInternal;
						}
						catch
						{
							consumedSize = ErrorInternal;
						}
						finally
						{
							Monitor.Exit(csDispatching);
						}

						if (consumedSize < 0)
						{
							if (UAStatusCode == (uint)StatusCode.Good)
							{
								if (consumedSize == ErrorInternal) { UAStatusCode = (uint)StatusCode.BadInternalError; }
								if (consumedSize == ErrorParseFail) { UAStatusCode = (uint)StatusCode.BadDecodingError; }
								if (consumedSize == ErrorRespWrite) { UAStatusCode = (uint)StatusCode.BadEncodingLimitsExceeded; }
							}

							// Handler failed
							recvAccumSize = -1;
							break;
						}
						else if (consumedSize == 0)
						{
							// Not enough to read a message
							break;
						}
						else if (consumedSize >= recvAccumSize)
						{
							if (consumedSize > recvAccumSize)
							{
								if (logger != null) { logger.Log(LogLevel.Error, string.Format("Consumed {0} but accumulated message size is {1}", consumedSize, recvAccumSize)); }
							}

							recvAccumSize = 0;
						}
						else
						{
							int newSize = recvAccumSize - consumedSize;

							var newRecvBuffer = new byte[maximumMessageSize];
							Array.Copy(recvBuffer, consumedSize, newRecvBuffer, 0, newSize);
							recvBuffer = newRecvBuffer;

							recvAccumSize = newSize;
						}

						if (UAStatusCode != (uint)StatusCode.Good)
						{
							threadAbort = true;
						}
					}

					// Cannot receive more or process existing
					if (recvAccumSize >= maximumMessageSize)
					{
						if (logger != null) { logger.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", recvAccumSize, maximumMessageSize)); }
						break;
					}

					if (recvAccumSize < 0)
					{
						break;
					}
				}

				if (UAStatusCode != (uint)StatusCode.Good)
				{
					TLError(UAStatusCode);
				}

				if (config.Session != null)
				{
					app.SessionRelease(config.Session);
				}

				socket.Shutdown(SocketShutdown.Send);
				socket.Close();
				server.RemoveDispatcher(this);

				//foreach (var cfg in monitorMap.Values)
				//{
				//	app.MonitorDispatcherRemove(cfg);
				//}

				if (logger != null) { logger.Log(LogLevel.Info, string.Format("Ended connection from {0}", sessionInfo.Endpoint)); }
			}

			virtual protected bool NeedsPulse()
			{
				return false;
			}

			virtual protected bool Pulse()
			{
				return false;
			}

			virtual protected int Consume(MemoryBuffer recvBuf)
			{
				return -1;
			}

			public void Close()
			{
				if (thread != null)
				{
					threadAbort = true;

					thread.Join();
					thread = null;
				}

				server.RemoveDispatcher(this);
			}
		}
	}
}
