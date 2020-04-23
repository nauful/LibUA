using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using LibUA.Core;

namespace LibUA
{
	public class Client : IDisposable
	{
		// Message type, message size, secure channel ID, security token ID
		const int MessageEncodedBlockStart = 16;
		const int ChunkHeaderOverhead = 4 * 6;

		const double UsableMessageSizeFactor = 0.8;
		const int TLPaddingOverhead = 1024;

		public delegate void ConnectionClosed();
		public event ConnectionClosed OnConnectionClosed = null;

		public const int ListenerInterval = 100;

		public readonly string Target;
		public readonly int Port;
		public readonly int Timeout;

		protected SLChannel config = null;
		int MaximumMessageSize;

		Semaphore cs = null;
		Semaphore csDispatching = null;
		Semaphore csWaitForSecure = null;
		uint nextRequestHandle = 0;

		protected TcpClient tcp = null;

		protected Thread thread = null;
		bool threadAbort = false;

		long totalBytesSent = 0, totalBytesRecv = 0;

		System.Timers.Timer renewTimer = null;

		class RecvHandler
		{
			public MemoryBuffer RecvBuf { get; set; }
			public NodeId Type { get; set; }
			public ResponseHeader Header { get; set; }
		}

		HashSet<Tuple<uint, uint>> recvPendingRequests = null;
		Dictionary<Tuple<uint, uint>, RecvHandler> recvQueue = null;
		Dictionary<Tuple<uint, uint>, ManualResetEvent> recvNotify = null;
		StatusCode recvHandlerStatus;

		bool nextPublish = false;
		HashSet<uint> publishReqs = null;

		public virtual X509Certificate2 ApplicationCertificate
		{
			get { return null; }
		}

		public virtual RSACryptoServiceProvider ApplicationPrivateKey
		{
			get { return null; }
		}

		public long TotalBytesSent
		{
			get { return totalBytesSent; }
		}

		public long TotalBytesRecv
		{
			get { return totalBytesRecv; }
		}

		public bool IsConnected
		{
			get { return tcp != null && tcp.Connected; }
		}

		public Client(string Target, int Port, int Timeout, int MaximumMessageSize = 1 << 18)
		{
			this.Target = Target;
			this.Port = Port;
			this.Timeout = Timeout;
			this.MaximumMessageSize = MaximumMessageSize;
		}

		public StatusCode OpenSecureChannel(MessageSecurityMode messageSecurityMode, SecurityPolicy securityPolicy, byte[] serverCert)
		{
			config.SecurityPolicy = securityPolicy;
			config.MessageSecurityMode = messageSecurityMode;
			config.RemoteCertificateString = serverCert;

			try
			{
				config.RemoteCertificate = new X509Certificate2(serverCert);
			}
			catch
			{
				return StatusCode.BadCertificateInvalid;
			}

			try
			{
				return OpenSecureChannelInternal(false);
			}
			finally
			{
				csWaitForSecure.Release();
			}
		}

		StatusCode RenewSecureChannel()
		{
			try
			{
				return OpenSecureChannelInternal(true);
			}
			finally
			{
				csWaitForSecure.Release();
			}
		}

		StatusCode OpenSecureChannelInternal(bool renew)
		{
			SecurityTokenRequestType requestType = renew ?
				SecurityTokenRequestType.Renew : SecurityTokenRequestType.Issue;

			try
			{
				cs.WaitOne();

				var sendBuf = new MemoryBuffer(MaximumMessageSize);

				if (requestType == SecurityTokenRequestType.Issue)
				{
					config.ChannelID = 0;
				}

				bool succeeded = true;
				succeeded &= sendBuf.Encode((uint)(MessageType.Open) | ((uint)'F' << 24));
				succeeded &= sendBuf.Encode((uint)0);
				succeeded &= sendBuf.Encode(config.ChannelID);
				succeeded &= sendBuf.EncodeUAString(Types.SLSecurityPolicyUris[(int)config.SecurityPolicy]);
				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					succeeded &= sendBuf.EncodeUAByteString(null);
					succeeded &= sendBuf.EncodeUAByteString(null);
				}
				else
				{
					var certStr = ApplicationCertificate.Export(X509ContentType.Cert);
					var serverCertThumbprint = UASecurity.SHACalculate(config.RemoteCertificateString, SecurityPolicy.Basic128Rsa15);

					succeeded &= sendBuf.EncodeUAByteString(certStr);
					succeeded &= sendBuf.EncodeUAByteString(serverCertThumbprint);
				}

				int asymCryptFrom = sendBuf.Position;

				if (requestType == SecurityTokenRequestType.Issue)
				{
					config.LocalSequence = new SLSequence()
					{
						SequenceNumber = 51,
						RequestId = 1,
					};
				}

				succeeded &= sendBuf.Encode(config.LocalSequence.SequenceNumber);
				succeeded &= sendBuf.Encode(config.LocalSequence.RequestId);

				succeeded &= sendBuf.Encode(new NodeId(RequestCode.OpenSecureChannelRequest));

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				UInt32 clientProtocolVersion = 0;
				UInt32 securityTokenRequestType = (uint)requestType;
				UInt32 messageSecurityMode = (uint)config.MessageSecurityMode;
				byte[] clientNonce = null;
				UInt32 reqLifetime = 30 * 10000;

				if (config.SecurityPolicy != SecurityPolicy.None)
				{
					int symKeySize = UASecurity.SymmetricKeySizeForSecurityPolicy(config.SecurityPolicy);
					clientNonce = UASecurity.GenerateRandomBytes(symKeySize);
				}

				succeeded &= sendBuf.Encode(reqHeader);
				succeeded &= sendBuf.Encode(clientProtocolVersion);
				succeeded &= sendBuf.Encode(securityTokenRequestType);
				succeeded &= sendBuf.Encode(messageSecurityMode);
				succeeded &= sendBuf.EncodeUAByteString(clientNonce);
				succeeded &= sendBuf.Encode(reqLifetime);

				config.LocalNonce = clientNonce;

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
				}

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					MarkPositionAsSize(sendBuf);
				}
				else
				{
					var padMethod = UASecurity.PaddingMethodForSecurityPolicy(config.SecurityPolicy);
					int sigSize = UASecurity.CalculateSignatureSize(ApplicationCertificate);
					int padSize = UASecurity.CalculatePaddingSize(config.RemoteCertificate, config.SecurityPolicy, sendBuf.Position - asymCryptFrom, sigSize);

					if (padSize > 0)
					{
						byte paddingValue = (byte)((padSize - 1) & 0xFF);

						var appendPadding = new byte[padSize];
						for (int i = 0; i < padSize; i++) { appendPadding[i] = paddingValue; }
						sendBuf.Append(appendPadding);
					}

					int respSize = sendBuf.Position + sigSize;

					respSize = asymCryptFrom + UASecurity.CalculateEncryptedSize(config.RemoteCertificate, respSize - asymCryptFrom, padMethod);
					MarkPositionAsSize(sendBuf, (UInt32)respSize);

					var msgSign = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(sendBuf.Buffer, 0, sendBuf.Position),
						ApplicationPrivateKey, config.SecurityPolicy);
					sendBuf.Append(msgSign);

					var packed = UASecurity.RsaPkcs15Sha_Encrypt(
						new ArraySegment<byte>(sendBuf.Buffer, asymCryptFrom, sendBuf.Position - asymCryptFrom),
						config.RemoteCertificate, config.SecurityPolicy);

					sendBuf.Position = asymCryptFrom;
					sendBuf.Append(packed);

					if (sendBuf.Position != respSize)
					{
						return StatusCode.BadSecurityChecksFailed;
					}
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Open, 0);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				tcp.Client.Send(sendBuf.Buffer, sendBuf.Position, SocketFlags.None);
				Interlocked.Add(ref totalBytesSent, sendBuf.Position);

				config.LocalSequence.SequenceNumber++;
				uint reqId = config.LocalSequence.RequestId++;

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					var key = new Tuple<uint, uint>((uint)MessageType.Open, 0);
					if (!recvQueue.TryGetValue(key, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(key);
				}

				UInt32 secureChannelId;
				string securityPolicyUri;
				byte[] senderCertificate, recvCertThumbprint;
				UInt32 respSequenceNumber, respRequestId;
				NodeId messageType;

				if (!recvHandler.RecvBuf.Decode(out secureChannelId)) { return StatusCode.BadDecodingError; }

				if (!recvHandler.RecvBuf.DecodeUAString(out securityPolicyUri)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.DecodeUAByteString(out senderCertificate)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.DecodeUAByteString(out recvCertThumbprint)) { return StatusCode.BadDecodingError; }

				try
				{
					if (securityPolicyUri != Types.SLSecurityPolicyUris[(int)config.SecurityPolicy])
					{
						return StatusCode.BadSecurityPolicyRejected;
					}
				}
				catch
				{
					return StatusCode.BadSecurityPolicyRejected;
				}

				// Check in the middle for buffer decrypt
				if (config.SecurityPolicy != SecurityPolicy.None)
				{
					try
					{

						config.RemoteCertificate = new X509Certificate2(senderCertificate);
						if (!UASecurity.VerifyCertificate(config.RemoteCertificate))
						{
							return StatusCode.BadCertificateInvalid;
						}
					}
					catch
					{
						return StatusCode.BadCertificateInvalid;
					}

					var appCertStr = ApplicationCertificate.Export(X509ContentType.Cert);
					if (!UASecurity.SHAVerify(appCertStr, recvCertThumbprint, SecurityPolicy.Basic128Rsa15))
					{
						return StatusCode.BadSecurityChecksFailed;
					}

					var paddingMethod = UASecurity.PaddingMethodForSecurityPolicy(config.SecurityPolicy);
					var asymDecBuf = UASecurity.RsaPkcs15Sha_Decrypt(
						new ArraySegment<byte>(recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position),
						ApplicationCertificate, ApplicationPrivateKey, config.SecurityPolicy);

					int minPlainSize = Math.Min(asymDecBuf.Length, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position);
					Array.Copy(asymDecBuf, 0, recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, minPlainSize);
				}

				if (!recvHandler.RecvBuf.Decode(out respSequenceNumber)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out respRequestId)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out messageType)) { return StatusCode.BadDecodingError; }

				if (!messageType.EqualsNumeric(0, (uint)RequestCode.OpenSecureChannelResponse))
				{
					return StatusCode.BadSecureChannelClosed;
				}

				if (!renew)
				{
					config.RemoteSequence = new SLSequence()
					{
						RequestId = respRequestId,
						SequenceNumber = respSequenceNumber
					};
				}

				ResponseHeader respHeader = null;
				if (!recvHandler.RecvBuf.Decode(out respHeader)) { return StatusCode.BadDecodingError; }

				UInt32 serverProtocolVersion;
				UInt32 channelId, tokenId;
				UInt64 createAtTimestamp;
				UInt32 respLifetime;
				byte[] serverNonce;

				if (!recvHandler.RecvBuf.Decode(out serverProtocolVersion)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out channelId)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out tokenId)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out createAtTimestamp)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.Decode(out respLifetime)) { return StatusCode.BadDecodingError; }
				if (!recvHandler.RecvBuf.DecodeUAByteString(out serverNonce)) { return StatusCode.BadDecodingError; }

				if (renew)
				{
					config.PrevChannelID = config.ChannelID;
					config.PrevTokenID = config.TokenID;
				}

				config.ChannelID = channelId;
				config.TokenID = tokenId;
				config.TokenCreatedAt = DateTimeOffset.FromFileTime((long)createAtTimestamp);
				config.TokenLifetime = respLifetime;
				config.RemoteNonce = serverNonce;

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					config.LocalKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
					config.RemoteKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
				}
				else
				{
					int symKeySize = UASecurity.SymmetricKeySizeForSecurityPolicy(config.SecurityPolicy);

					int sigKeySize = UASecurity.SymmetricSignatureKeySizeForSecurityPolicy(config.SecurityPolicy);
					int symBlockSize = UASecurity.SymmetricBlockSizeForSecurityPolicy(config.SecurityPolicy);

					var clientHash = UASecurity.PSHA(
						config.RemoteNonce,
						config.LocalNonce,
						sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

					var newLocalKeyset = new SLChannel.Keyset(
						(new ArraySegment<byte>(clientHash, 0, sigKeySize)).ToArray(),
						(new ArraySegment<byte>(clientHash, sigKeySize, symKeySize)).ToArray(),
						(new ArraySegment<byte>(clientHash, sigKeySize + symKeySize, symBlockSize)).ToArray());

					var serverHash = UASecurity.PSHA(
						config.LocalNonce,
						config.RemoteNonce,
						sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

					var newRemoteKeyset = new SLChannel.Keyset(
						(new ArraySegment<byte>(serverHash, 0, sigKeySize)).ToArray(),
						(new ArraySegment<byte>(serverHash, sigKeySize, symKeySize)).ToArray(),
						(new ArraySegment<byte>(serverHash, sigKeySize + symKeySize, symBlockSize)).ToArray());

					//Console.WriteLine("Local nonce: {0}", string.Join("", config.LocalNonce.Select(v => v.ToString("X2"))));
					//Console.WriteLine("Remote nonce: {0}", string.Join("", config.RemoteNonce.Select(v => v.ToString("X2"))));

					//Console.WriteLine("RSymSignKey: {0}", string.Join("", newRemoteKeyset.SymSignKey.Select(v => v.ToString("X2"))));
					//Console.WriteLine("RSymEncKey: {0}", string.Join("", newRemoteKeyset.SymEncKey.Select(v => v.ToString("X2"))));
					//Console.WriteLine("RSymIV: {0}", string.Join("", newRemoteKeyset.SymIV.Select(v => v.ToString("X2"))));

					//Console.WriteLine("LSymSignKey: {0}", string.Join("", newLocalKeyset.SymSignKey.Select(v => v.ToString("X2"))));
					//Console.WriteLine("LSymEncKey: {0}", string.Join("", newLocalKeyset.SymEncKey.Select(v => v.ToString("X2"))));
					//Console.WriteLine("LSymIV: {0}", string.Join("", newLocalKeyset.SymIV.Select(v => v.ToString("X2"))));

					if (config.LocalKeysets == null)
					{
						config.LocalKeysets = new SLChannel.Keyset[2] { newLocalKeyset, new SLChannel.Keyset() };
						config.RemoteKeysets = new SLChannel.Keyset[2] { newRemoteKeyset, new SLChannel.Keyset() };
					}
					else
					{
						config.LocalKeysets = new SLChannel.Keyset[2] { newLocalKeyset, config.LocalKeysets[0] };
						config.RemoteKeysets = new SLChannel.Keyset[2] { newRemoteKeyset, config.RemoteKeysets[0] };
					}
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();

				if (!renew)
				{
					CheckPostCall();
				}
			}
		}

		StatusCode EncodeMessageHeader(MemoryBuffer sendBuf, bool needsEstablishedSL = true)
		{
			if (config.SLState != ConnectionState.Established && needsEstablishedSL)
			{
				return StatusCode.BadSecureChannelClosed;
			}

			bool succeeded = true;
			succeeded &= sendBuf.Encode((uint)(MessageType.Message) | ((uint)'F' << 24));
			succeeded &= sendBuf.Encode((uint)0);
			succeeded &= sendBuf.Encode(config.ChannelID);
			succeeded &= sendBuf.Encode(config.TokenID);
			succeeded &= sendBuf.Encode(config.LocalSequence.SequenceNumber);
			succeeded &= sendBuf.Encode(config.LocalSequence.RequestId);

			if (!succeeded)
			{
				return StatusCode.BadEncodingLimitsExceeded;
			}

			config.LocalSequence.SequenceNumber++;
			config.LocalSequence.RequestId++;

			return StatusCode.Good;
		}

		public StatusCode GetEndpoints(out EndpointDescription[] endpointDescs, string[] localeIDs)
		{
			endpointDescs = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.GetEndpointsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.EncodeUAString(string.Format("opc.tcp://{0}:{1}", config.Endpoint.Address.ToString(), config.Endpoint.Port.ToString()));
				// LocaleIds
				succeeded &= sendBuf.EncodeUAString(localeIDs);
				// ProfileUris
				succeeded &= sendBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.GetEndpointsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numEndpointDescs;
				succeeded &= recvHandler.RecvBuf.Decode(out numEndpointDescs);

				endpointDescs = new EndpointDescription[numEndpointDescs];
				for (int i = 0; i < numEndpointDescs && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out endpointDescs[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode FindServers(out ApplicationDescription[] results, string[] localeIDs)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.FindServersRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.EncodeUAString(string.Format("opc.tcp://{0}:{1}", config.Endpoint.Address.ToString(), config.Endpoint.Port.ToString()));
				// LocaleIds
				succeeded &= sendBuf.EncodeUAString(localeIDs);
				// ProfileIds
				succeeded &= sendBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.FindServersResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numDescs;
				succeeded &= recvHandler.RecvBuf.Decode(out numDescs);

				results = new ApplicationDescription[numDescs];
				for (int i = 0; i < numDescs && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		private StatusCode MessageSecureAndSend(SLChannel config, MemoryBuffer respBuf)
		{
			// TL header, sequence header
			const int ChunkHeaderOverhead = 4 * 6;
			const int seqPosition = 4 * 4;

			int chunkSize = (int)config.TL.RemoteConfig.RecvBufferSize - ChunkHeaderOverhead - TLPaddingOverhead;
			//int chunkSize = 2048 - ChunkHeaderOverhead - TLPaddingOverhead;
			int numChunks = (respBuf.Position - ChunkHeaderOverhead + chunkSize - 1) / chunkSize;

			if (numChunks > 1 &&
				numChunks > config.TL.RemoteConfig.MaxChunkCount)
			{
				return StatusCode.BadEncodingLimitsExceeded;
			}

			if (numChunks > 1)
			{
				//Console.WriteLine("{0} -> {1} chunks", respBuf.Position, numChunks);
				var chunk = new MemoryBuffer(chunkSize + ChunkHeaderOverhead + TLPaddingOverhead);
				for (int i = 0; i < numChunks; i++)
				{
					bool isFinal = i == numChunks - 1;

					chunk.Rewind();
					int offset = i * chunkSize;
					int curSize = isFinal ?
						respBuf.Position - ChunkHeaderOverhead - offset :
						chunkSize;

					chunk.Append(respBuf.Buffer, 0, ChunkHeaderOverhead);
					if (i > 0)
					{
						chunk.Encode(config.LocalSequence.SequenceNumber, seqPosition);
						config.LocalSequence.SequenceNumber++;
					}

					chunk.Buffer[3] = isFinal ? (byte)'F' : (byte)'C';
					chunk.Append(respBuf.Buffer, ChunkHeaderOverhead + offset, curSize);

					if (config.MessageSecurityMode == MessageSecurityMode.None)
					{
						MarkPositionAsSize(chunk);
					}
					else
					{
						var secureRes = UASecurity.SecureSymmetric(chunk, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

						if (!Types.StatusCodeIsGood((uint)secureRes))
						{
							return secureRes;
						}
					}

					tcp.Client.Send(chunk.Buffer, chunk.Position, SocketFlags.None);
					Interlocked.Add(ref totalBytesSent, chunk.Position);
				}
			}
			else
			{
				if (config.MessageSecurityMode == MessageSecurityMode.None)
				{
					MarkPositionAsSize(respBuf);
				}
				else
				{
					var secureRes = UASecurity.SecureSymmetric(respBuf, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

					if (!Types.StatusCodeIsGood((uint)secureRes))
					{
						return secureRes;
					}
				}

				if (!IsConnected)
				{
					return StatusCode.BadConnectionClosed;
				}

				tcp.Client.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
				Interlocked.Add(ref totalBytesSent, respBuf.Position);
			}

			return StatusCode.Good;
		}

		public StatusCode Connect()
		{
			cs = new Semaphore(1, 1);

			try
			{
				cs.WaitOne();

				if (IsConnected)
				{
					Disconnect();
				}

				totalBytesSent = 0;
				totalBytesRecv = 0;

				try
				{
					tcp = new TcpClient(Target, Port);
				}
				catch (SocketException)
				{
					return StatusCode.BadConnectionRejected;
				}

				csDispatching = new Semaphore(1, 1);
				csWaitForSecure = new Semaphore(0, 1);

				nextRequestHandle = 0;

				tcp.LingerState = new LingerOption(true, Timeout);
				tcp.NoDelay = true;
				tcp.Client.NoDelay = true;

				config = new SLChannel();
				config.Endpoint = tcp.Client.RemoteEndPoint as IPEndPoint;
				config.SLState = ConnectionState.Opening;

				recvQueue = new Dictionary<Tuple<uint, uint>, RecvHandler>();
				recvNotify = new Dictionary<Tuple<uint, uint>, ManualResetEvent>();
				recvPendingRequests = new HashSet<Tuple<uint, uint>>();
				publishReqs = new HashSet<uint>();

				recvHandlerStatus = StatusCode.Good;

				threadAbort = false;
				thread = new Thread(new ParameterizedThreadStart(ThreadTarget));
				thread.Start(this);

				var ret = SendHello();
				if (ret != StatusCode.Good)
				{
					return ret;
				}

				return ret;
			}
			finally
			{
				cs.Release();
			}
		}

		private StatusCode SendHello()
		{
			var sendBuf = new MemoryBuffer(MaximumMessageSize);

			config.TL = new TLConnection();
			config.TL.LocalConfig = new TLConfiguration()
			{
				ProtocolVersion = 0,
				SendBufferSize = 1 << 16,
				RecvBufferSize = 1 << 16,
				MaxMessageSize = (uint)MaximumMessageSize,
				MaxChunkCount = 1337 + (uint)(MaximumMessageSize + ((1 << 16) - 1)) / (1 << 16),
			};

			bool succeeded = true;
			succeeded &= sendBuf.Encode((uint)(MessageType.Hello) | ((uint)'F' << 24));
			succeeded &= sendBuf.Encode((uint)0);
			succeeded &= sendBuf.Encode(config.TL.LocalConfig.ProtocolVersion);
			succeeded &= sendBuf.Encode(config.TL.LocalConfig.RecvBufferSize);
			succeeded &= sendBuf.Encode(config.TL.LocalConfig.SendBufferSize);
			succeeded &= sendBuf.Encode(config.TL.LocalConfig.MaxMessageSize);
			succeeded &= sendBuf.Encode(config.TL.LocalConfig.MaxChunkCount);
			succeeded &= sendBuf.EncodeUAString(string.Format("opc.tcp://{0}:{1}", config.Endpoint.Address.ToString(), config.Endpoint.Port.ToString()));

			if (!succeeded)
			{
				return StatusCode.BadEncodingLimitsExceeded;
			}

			MarkPositionAsSize(sendBuf);

			var recvKey = new Tuple<uint, uint>((uint)MessageType.Acknowledge, 0);
			var recvEv = new ManualResetEvent(false);
			lock (recvNotify)
			{
				recvNotify[recvKey] = recvEv;
			}

			tcp.Client.Send(sendBuf.Buffer, sendBuf.Position, SocketFlags.None);
			Interlocked.Add(ref totalBytesSent, sendBuf.Position);

			bool signalled = recvEv.WaitOne(Timeout * 1000);

			lock (recvNotify)
			{
				recvNotify.Remove(recvKey);
			}

			if (recvHandlerStatus != StatusCode.Good)
			{
				return recvHandlerStatus;
			}

			if (!signalled)
			{
				return StatusCode.BadRequestTimeout;
			}

			RecvHandler recvHandler;
			lock (recvQueue)
			{
				var key = new Tuple<uint, uint>((uint)MessageType.Acknowledge, 0);
				if (!recvQueue.TryGetValue(key, out recvHandler))
				{
					return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
				}

				recvQueue.Remove(key);
			}

			config.TL.RemoteConfig = new TLConfiguration();
			if (!recvHandler.RecvBuf.Decode(out config.TL.RemoteConfig.ProtocolVersion)) { return StatusCode.BadDecodingError; }
			if (!recvHandler.RecvBuf.Decode(out config.TL.RemoteConfig.RecvBufferSize)) { return StatusCode.BadDecodingError; }
			if (!recvHandler.RecvBuf.Decode(out config.TL.RemoteConfig.SendBufferSize)) { return StatusCode.BadDecodingError; }
			if (!recvHandler.RecvBuf.Decode(out config.TL.RemoteConfig.MaxMessageSize)) { return StatusCode.BadDecodingError; }
			if (!recvHandler.RecvBuf.Decode(out config.TL.RemoteConfig.MaxChunkCount)) { return StatusCode.BadDecodingError; }

			MaximumMessageSize = (int)Math.Min(config.TL.RemoteConfig.MaxMessageSize, MaximumMessageSize);

			//if (!signalled)
			//{
			//	RemovePendingRequest(RequestId);

			//	// Clear if received between Wait and Remove
			//	if (semRecvMsg.WaitOne(0))
			//	{
			//		// Clean up message
			//		RemovePendingRequest(RequestId);
			//	}

			//	return DXPStatusCode.BadNoResponse;
			//}

			return StatusCode.Good;
		}

		protected void MarkPositionAsSize(MemoryBuffer mb, UInt32 position)
		{
			int restorePos = mb.Position;
			mb.Position = 4;
			mb.Encode(position);
			mb.Position = restorePos;
		}

		// Skip MessageType and ChunkType, write MessageSize
		protected void MarkPositionAsSize(MemoryBuffer mb)
		{
			UInt32 pos = (UInt32)mb.Position;
			mb.Position = 4;
			mb.Encode(pos);
			mb.Position = (int)pos;
		}

		public void Dispose()
		{
			Disconnect();
		}

		public StatusCode Disconnect()
		{
			nextPublish = false;

			if (renewTimer != null)
			{
				try
				{
					cs.WaitOne();
					renewTimer.Stop();
				}
				finally
				{
					cs.Release();
				}

				renewTimer = null;
			}

			if (thread != null)
			{
				threadAbort = true;

				thread.Join();
				thread = null;
			}

			if (tcp == null)
			{
				return StatusCode.BadNotConnected;
			}

			CloseConnection();
			return StatusCode.Good;
		}

		private void CloseConnection()
		{
			try
			{
				if (tcp != null)
				{
					tcp.Client.Shutdown(SocketShutdown.Both);
					tcp.Close();

					if (OnConnectionClosed != null)
					{
						OnConnectionClosed();
					}
				}
			}
			finally
			{
				tcp = null;
			}
		}

		~Client() { Dispose(); }

		private static void ThreadTarget(object args)
		{
			(args as Client).ThreadTarget();
		}

		private void ThreadTarget()
		{
			var socket = tcp.Client;

			int recvAccumSize = 0;
			var recvBuffer = new byte[MaximumMessageSize];

			while (IsConnected)
			{
				if (threadAbort)
				{
					break;
				}

				if (!socket.Poll(ListenerInterval * 1000, SelectMode.SelectRead))
				{
					continue;
				}

				int bytesRead = 0;
				int bytesAvailable = MaximumMessageSize - recvAccumSize;
				if (bytesAvailable > 0)
				{
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

					Interlocked.Add(ref totalBytesRecv, bytesRead);
				}
				else
				{
					break;
				}

				recvAccumSize += bytesRead;
				if (recvAccumSize > MaximumMessageSize)
				{
					break;
				}

				while (recvAccumSize > 0)
				{
					csDispatching.WaitOne();
					int consumedSize = -1;

					try
					{
						//var sw = new System.Diagnostics.Stopwatch();
						//sw.Start();
						consumedSize = Consume(config, new MemoryBuffer(recvBuffer, recvAccumSize));
						//sw.Stop();
						//if (consumedSize > 0)
						//{
						//	Console.WriteLine("Client consumed {0} in {1}, total {2}", consumedSize, sw.Elapsed.ToString(), recvAccumSize);
						//}
					}
					catch
					{
						recvHandlerStatus = StatusCode.BadDecodingError;
						consumedSize = -1;
					}
					finally
					{
						csDispatching.Release();
					}

					if (consumedSize == -1)
					{
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
							throw new Exception(string.Format("Consumed {0} but accumulated message size is {1}", consumedSize, recvAccumSize));
						}

						recvAccumSize = 0;
					}
					else
					{
						int newSize = recvAccumSize - consumedSize;

						var newRecvBuffer = new byte[MaximumMessageSize];
						Array.Copy(recvBuffer, consumedSize, newRecvBuffer, 0, newSize);
						recvBuffer = newRecvBuffer;

						recvAccumSize = newSize;
					}
				}

				CheckPostCall();

				// Cannot receive more or process existing
				if (recvAccumSize == -1 || recvAccumSize >= MaximumMessageSize)
				{
					break;
				}
			}

			CloseConnection();

			//if (DXPStatusCode.IsGood(connStatus))
			//{
			//	connStatus = DXPStatusCode.BadNotConnected;
			//}

			// Fail any pending calls with connStatus
			//semRecvMsg.Release();

			lock (recvNotify)
			{
				foreach (var kvp in recvNotify)
				{
					kvp.Value.Set();
				}
			}

			lock (recvQueue)
			{
				foreach (var notifyAbort in recvNotify)
				{
					notifyAbort.Value.Set();
				}
			}
		}

		private void CheckPostCall()
		{
			if (nextPublish)
			{
				if (PublishRequest() != StatusCode.GoodCallAgain)
				{
					nextPublish = false;
				}
			}
		}

		bool ChunkReconstruct(MemoryBuffer buf, List<uint> chunkLengths)
		{
			if (buf.Capacity < ChunkHeaderOverhead)
			{
				return false;
			}

			uint totalLength = 0;
			for (int i = 0; i < chunkLengths.Count; i++)
			{
				if (i == 0)
				{
					totalLength += chunkLengths[i];
				}
				else
				{
					if (chunkLengths[i] < ChunkHeaderOverhead)
					{
						return false;
					}

					totalLength += chunkLengths[i] - ChunkHeaderOverhead;
				}
			}

			uint readOffset = 0, writeOffset = ChunkHeaderOverhead;
			for (int i = 0; i < chunkLengths.Count; i++)
			{
				uint len = chunkLengths[i];

				if (i > 0)
				{
					Array.Copy(buf.Buffer, (int)(readOffset + ChunkHeaderOverhead), buf.Buffer, (int)writeOffset, (int)(len - ChunkHeaderOverhead));
				}

				readOffset += len;
				writeOffset += len - ChunkHeaderOverhead;
			}

			buf.Buffer[3] = (byte)'F';
			MarkPositionAsSize(buf, totalLength);

			return true;
		}

		MemoryBuffer ChunkReconstructSecured(MemoryBuffer buf, List<uint> chunkLengths, SLChannel config)
		{
			if (buf.Capacity < ChunkHeaderOverhead)
			{
				return null;
			}

			MemoryBuffer tmpBuf = new MemoryBuffer(buf.Capacity);
			MemoryBuffer recvBuf = new MemoryBuffer(buf.Capacity);

			uint readOffset = 0;
			int decodedDecrTotal = 0;
			for (int i = 0; i < chunkLengths.Count; i++)
			{
				uint len = chunkLengths[i];
				Array.Copy(buf.Buffer, readOffset, tmpBuf.Buffer, 0, (int)len);

				tmpBuf.Position = 3;
				int decrSize = 0;
				var unsecureRes = (uint)UASecurity.UnsecureSymmetric(tmpBuf, config.TokenID, config.PrevTokenID, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out decrSize);
				if (!Types.StatusCodeIsGood(unsecureRes))
				{
					return null;
				}

				decodedDecrTotal += decrSize;

				if (i == 0)
				{
					Array.Copy(tmpBuf.Buffer, 0, recvBuf.Buffer, 0, ChunkHeaderOverhead);
					recvBuf.Buffer[3] = (byte)'F';
					recvBuf.Position = ChunkHeaderOverhead;
				}

				recvBuf.Append(tmpBuf.Buffer, ChunkHeaderOverhead, (int)(decrSize - ChunkHeaderOverhead));
				readOffset += len;
			}

			MarkPositionAsSize(recvBuf);

			return recvBuf;
		}

		List<uint> ChunkCalculateSizes(MemoryBuffer memBuf)
		{
			var chunkLengths = new List<uint>();

			uint offset = 0;
			while (true)
			{
				// Incomplete with no final
				if (memBuf.Capacity < offset + ChunkHeaderOverhead)
				{
					return null;
				}

				byte chunkType = memBuf.Buffer[offset + 3];
				if (chunkType != 'C' && chunkType != 'F')
				{
					// Invalid chunk type
					return null;
				}

				bool isFinal = chunkType == (byte)'F';
				UInt32 chunkLength;
				if (!memBuf.Decode(out chunkLength, (int)offset + 4))
				{
					return null;
				}

				chunkLengths.Add(chunkLength);
				offset += chunkLength;

				if (isFinal)
				{
					break;
				}
			}

			return chunkLengths;
		}

		private int Consume(SLChannel config, MemoryBuffer recvBuf)
		{
			// No message type and size
			if (recvBuf.Capacity < 8)
			{
				return 0;
			}

			uint messageType = (uint)recvBuf.Buffer[0] | (uint)(recvBuf.Buffer[1] << 8) | (uint)(recvBuf.Buffer[2] << 16);

			uint messageSize = 0;
			if (recvBuf.Buffer[3] == 'F')
			{
				messageSize =
					(uint)recvBuf.Buffer[4] | (uint)(recvBuf.Buffer[5] << 8) |
					(uint)(recvBuf.Buffer[6] << 16) | (uint)(recvBuf.Buffer[7] << 24);

				if (config != null && config.TL != null &&
					messageSize > config.TL.LocalConfig.MaxMessageSize)
				{
					recvHandlerStatus = StatusCode.BadResponseTooLarge;
					return -1;
				}

				if (messageSize > recvBuf.Capacity)
				{
					return 0;
				}

				if (messageType == (uint)MessageType.Message ||
					messageType == (uint)MessageType.Close)
				{
					if (config.MessageSecurityMode > MessageSecurityMode.None &&
						config.LocalKeysets != null && config.RemoteKeysets != null)
					{
						int restorePos = recvBuf.Position;

						recvBuf.Position = 3;
						int decrSize = 0;

						var unsecureRes = (uint)UASecurity.UnsecureSymmetric(recvBuf, config.TokenID, config.PrevTokenID, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out decrSize);

						recvBuf.Position = restorePos;

						if (!Types.StatusCodeIsGood(unsecureRes))
						{
							return -1;
						}
					}
				}
			}
			else if (recvBuf.Buffer[3] == 'C')
			{
				var chunkSizes = ChunkCalculateSizes(recvBuf);
				if (chunkSizes == null)
				{
					return 0;
				}

				if (config.MessageSecurityMode > MessageSecurityMode.None &&
					config.LocalKeysets != null && config.RemoteKeysets != null)
				{
					recvBuf = ChunkReconstructSecured(recvBuf, chunkSizes, config);

					if (recvBuf == null)
					{
						recvHandlerStatus = StatusCode.BadMessageNotAvailable;
						return -1;
					}
				}
				else
				{
					if (!ChunkReconstruct(recvBuf, chunkSizes))
					{
						recvHandlerStatus = StatusCode.BadMessageNotAvailable;
						return -1;
					}
				}

				messageSize = 0;
				foreach (var chunkSize in chunkSizes) { messageSize += chunkSize; }

				if (messageSize > recvBuf.Capacity)
				{
					return 0;
				}
			}
			else
			{
				recvHandlerStatus = StatusCode.BadMessageNotAvailable;
				return -1;
			}

			recvBuf.Position = 8;

			if (messageType == (uint)MessageType.Acknowledge)
			{
				lock (recvQueue)
				{
					var key = new Tuple<uint, uint>(messageType, 0);
					recvQueue[key] = new RecvHandler()
					{
						Header = null,
						RecvBuf = recvBuf.Duplicate(),
						Type = NodeId.Zero
					};

					ManualResetEvent ev = null;
					if (recvNotify.TryGetValue(key, out ev))
					{
						ev.Set();
					}
				}
			}
			else if (messageType == (uint)MessageType.Open)
			{
				ManualResetEvent ev = null;

				lock (recvQueue)
				{
					var key = new Tuple<uint, uint>(messageType, 0);
					recvQueue[key] = new RecvHandler()
					{
						Header = null,
						RecvBuf = recvBuf.Duplicate(),
						Type = NodeId.Zero
					};

					if (recvNotify.TryGetValue(key, out ev))
					{
						ev.Set();
					}
				}

				// Wait for secure channel renew response to be
				// processed before handling other messages
				if (ev != null)
				{
					csWaitForSecure.WaitOne();
				}
			}
			else if (messageType == (uint)MessageType.Error)
			{
				recvHandlerStatus = StatusCode.BadCommunicationError;

				UInt32 status;
				try
				{
					if (recvBuf.Decode(out status))
					{
						recvHandlerStatus = (StatusCode)status;
					}
				}
				catch
				{
				}

				return -1;
			}
			else
			{
				UInt32 secureChannelId, securityTokenId, securitySeqNum, securityReqId;

				bool succeeded = true;
				succeeded &= recvBuf.Decode(out secureChannelId);
				succeeded &= recvBuf.Decode(out securityTokenId);
				succeeded &= recvBuf.Decode(out securitySeqNum);
				succeeded &= recvBuf.Decode(out securityReqId);

				config.RemoteSequence.SequenceNumber = securitySeqNum;

				NodeId typeId;
				succeeded &= recvBuf.Decode(out typeId);

				ResponseHeader respHeader;
				succeeded &= recvBuf.Decode(out respHeader);

				if (!succeeded)
				{
					recvHandlerStatus = StatusCode.BadDecodingError;
					return -1;
				}

				if (publishReqs.Contains(respHeader.RequestHandle))
				{
					ConsumeNotification(new RecvHandler()
					{
						Header = respHeader,
						RecvBuf = recvBuf.Duplicate(),
						Type = typeId
					});

					publishReqs.Remove(respHeader.RequestHandle);
					nextPublish = true;
				}
				else
				{
					lock (recvQueue)
					{
						var recvKey = new Tuple<uint, uint>(messageType, respHeader.RequestHandle);
						recvQueue[recvKey] = new RecvHandler()
						{
							Header = respHeader,
							RecvBuf = recvBuf.Duplicate(),
							Type = typeId
						};

						ManualResetEvent ev = null;
						if (recvNotify.TryGetValue(recvKey, out ev))
						{
							ev.Set();
						}
					}
				}
			}

			return (int)messageSize;
		}

		public StatusCode ActivateSession(object identityToken, string[] localeIDs, SecurityPolicy? userIdentitySecurityPolicy = null)
		{
			try
			{
				cs.WaitOne();

				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.ActivateSessionRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				if (config.MessageSecurityMode == MessageSecurityMode.None)
				{
					// ClientSignatureAlgorithm
					succeeded &= sendBuf.EncodeUAString((string)null);
					// ClientSignature
					succeeded &= sendBuf.EncodeUAByteString(null);
				}
				else
				{
					if (config.RemoteNonce == null)
					{
						return StatusCode.BadSessionClosed;
					}

					var strRemoteCert = config.RemoteCertificateString;
					var signMsg = new byte[strRemoteCert.Length + config.RemoteNonce.Length];
					Array.Copy(strRemoteCert, 0, signMsg, 0, strRemoteCert.Length);
					Array.Copy(config.RemoteNonce, 0, signMsg, strRemoteCert.Length, config.RemoteNonce.Length);

					var thumbprint = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(signMsg),
						ApplicationPrivateKey, config.SecurityPolicy);

					if (config.SecurityPolicy == SecurityPolicy.Basic256Sha256)
					{
						succeeded &= sendBuf.EncodeUAString(Types.SignatureAlgorithmSha256);
					}
					else
					{
						succeeded &= sendBuf.EncodeUAString(Types.SignatureAlgorithmSha1);
					}
					succeeded &= sendBuf.EncodeUAByteString(thumbprint);
				}

				// ClientSoftwareCertificates: Array of SignedSoftwareCertificate
				succeeded &= sendBuf.Encode((UInt32)0);

				// LocaleIds: Array of String
				succeeded &= sendBuf.EncodeUAString(localeIDs);

				if (identityToken is UserIdentityAnonymousToken)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.AnonymousIdentityToken_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);

					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.EncodeUAString((identityToken as UserIdentityAnonymousToken).PolicyId);
					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else if (identityToken is UserIdentityUsernameToken)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.UserNameIdentityToken_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);

					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.EncodeUAString(((identityToken as UserIdentityUsernameToken)).PolicyId);
					succeeded &= sendBuf.EncodeUAString(((identityToken as UserIdentityUsernameToken)).Username);

					try
					{
						var passwordSrc = (identityToken as UserIdentityUsernameToken).PasswordHash;
						int padSize = UASecurity.CalculatePaddingSize(config.RemoteCertificate,
							userIdentitySecurityPolicy ?? config.SecurityPolicy, 4 + passwordSrc.Length,
							(config.RemoteNonce == null ? 0 : config.RemoteNonce.Length));
						var rndBytes = UASecurity.GenerateRandomBytes(padSize);

						byte[] crypted = new byte[4 + passwordSrc.Length + padSize +
							(config.RemoteNonce == null ? 0 : config.RemoteNonce.Length)];

						int rawSize = passwordSrc.Length +
							(config.RemoteNonce == null ? 0 : config.RemoteNonce.Length);

						crypted[0] = (byte)(rawSize & 0xFF);
						crypted[1] = (byte)((rawSize >> 8) & 0xFF);
						crypted[2] = (byte)((rawSize >> 16) & 0xFF);
						crypted[3] = (byte)((rawSize >> 24) & 0xFF);

						Array.Copy(passwordSrc, 0, crypted, 4, passwordSrc.Length);

						int offset = 4 + passwordSrc.Length;

						if (config.RemoteNonce != null)
						{
							Array.Copy(config.RemoteNonce, 0, crypted, offset, config.RemoteNonce.Length);
							offset += config.RemoteNonce.Length;
						}

						Array.Copy(rndBytes, 0, crypted, offset, rndBytes.Length);
						offset += rndBytes.Length;

						crypted = UASecurity.RsaPkcs15Sha_Encrypt(
							new ArraySegment<byte>(crypted),
							config.RemoteCertificate, userIdentitySecurityPolicy ?? config.SecurityPolicy);

						succeeded &= sendBuf.EncodeUAByteString(crypted);
						succeeded &= sendBuf.EncodeUAString(((identityToken as UserIdentityUsernameToken)).Algorithm);
					}
					catch
					{
						return StatusCode.BadIdentityTokenInvalid;
					}

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else
				{
					throw new Exception(string.Format("Identity token of type {0} is not supported", identityToken.GetType().ToString()));
				}

				// TokenAlgorithm
				succeeded &= sendBuf.EncodeUAString((string)null);
				// TokenSignature
				succeeded &= sendBuf.EncodeUAByteString(null);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ActivateSessionResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				byte[] serverNonce;
				succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out serverNonce);
				config.RemoteNonce = serverNonce;

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				if (renewTimer != null)
				{
					renewTimer.Stop();
				}

				renewTimer = new System.Timers.Timer(0.7 * config.TokenLifetime);
				renewTimer.Elapsed += (sender, e) =>
				{
					var res = RenewSecureChannel();
					if (!Types.StatusCodeIsGood((uint)res))
					{
						recvHandlerStatus = res;
						Disconnect();
					}
				};
				renewTimer.Start();

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode CreateSession(ApplicationDescription appDesc, string sessionName, int requestedSessionTimeout)
		{
			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateSessionRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode(appDesc);
				// ServerUri
				succeeded &= sendBuf.EncodeUAString((string)null);
				succeeded &= sendBuf.EncodeUAString(string.Format("opc.tcp://{0}:{1}", config.Endpoint.Address.ToString(), config.Endpoint.Port.ToString()));
				succeeded &= sendBuf.EncodeUAString(sessionName);
				succeeded &= sendBuf.EncodeUAByteString(config.LocalNonce);
				if (ApplicationCertificate == null)
				{
					succeeded &= sendBuf.EncodeUAByteString(null);
				}
				else
				{
					succeeded &= sendBuf.EncodeUAByteString(ApplicationCertificate.Export(X509ContentType.Cert));
				}
				succeeded &= sendBuf.Encode((Double)(10000 * requestedSessionTimeout));
				succeeded &= sendBuf.Encode((UInt32)MaximumMessageSize);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateSessionResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				NodeId sessionIdToken, authToken;
				Double revisedSessionTimeout;
				succeeded &= recvHandler.RecvBuf.Decode(out sessionIdToken);
				succeeded &= recvHandler.RecvBuf.Decode(out authToken);
				succeeded &= recvHandler.RecvBuf.Decode(out revisedSessionTimeout);

				config.SessionIdToken = sessionIdToken;
				config.AuthToken = authToken;

				byte[] serverNonce, serverCert;
				succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out serverNonce);
				succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out serverCert);

				config.RemoteNonce = serverNonce;
				try
				{
					config.RemoteCertificate = new X509Certificate2(serverCert);
				}
				catch
				{
					return StatusCode.BadSecurityChecksFailed;
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode Read(ReadValueId[] Ids, out DataValue[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.ReadRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				// maxAge
				succeeded &= sendBuf.Encode((double)0);
				// LocaleIds
				succeeded &= sendBuf.Encode((UInt32)TimestampsToReturn.Both);
				succeeded &= sendBuf.Encode((UInt32)Ids.Length);
				for (int i = 0; i < Ids.Length; i++)
				{
					succeeded &= sendBuf.Encode(Ids[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ReadResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new DataValue[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				if (numRecv != Ids.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode Write(WriteValue[] Ids, out uint[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.WriteRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)Ids.Length);
				for (int i = 0; i < Ids.Length; i++)
				{
					succeeded &= sendBuf.Encode(Ids[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.WriteResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new uint[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				if (numRecv != Ids.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode Browse(BrowseDescription[] requests, uint requestedMaxReferencesPerNode, out BrowseResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.BrowseRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				// ViewId
				succeeded &= sendBuf.Encode(NodeId.Zero);
				// View timestamp
				succeeded &= sendBuf.Encode((UInt64)0);
				// View version
				succeeded &= sendBuf.Encode((UInt32)0);

				succeeded &= sendBuf.Encode((UInt32)requestedMaxReferencesPerNode);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.BrowseResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new BrowseResult[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					UInt32 status;
					byte[] contPoint;
					UInt32 numRefDesc;
					ReferenceDescription[] refDescs;

					succeeded &= recvHandler.RecvBuf.Decode(out status);
					succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out contPoint);
					succeeded &= recvHandler.RecvBuf.Decode(out numRefDesc);

					refDescs = new ReferenceDescription[numRefDesc];
					for (int j = 0; j < refDescs.Length; j++)
					{
						succeeded &= recvHandler.RecvBuf.Decode(out refDescs[j]);
					}

					results[i] = new BrowseResult(status, contPoint, refDescs);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				if (numRecv != requests.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode BrowseNext(IList<byte[]> contPoints, bool releaseContinuationPoints, out BrowseResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.BrowseNextRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode(releaseContinuationPoints);
				succeeded &= sendBuf.Encode((UInt32)contPoints.Count);
				for (int i = 0; i < contPoints.Count; i++)
				{
					succeeded &= sendBuf.EncodeUAByteString(contPoints[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.BrowseNextResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				if (!releaseContinuationPoints)
				{
					UInt32 numRecv;
					succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

					results = new BrowseResult[numRecv];
					for (int i = 0; i < numRecv && succeeded; i++)
					{
						UInt32 status;
						byte[] contPoint;
						UInt32 numRefDesc;
						ReferenceDescription[] refDescs;

						succeeded &= recvHandler.RecvBuf.Decode(out status);
						succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out contPoint);
						succeeded &= recvHandler.RecvBuf.Decode(out numRefDesc);

						refDescs = new ReferenceDescription[numRefDesc];
						for (int j = 0; j < refDescs.Length; j++)
						{
							succeeded &= recvHandler.RecvBuf.Decode(out refDescs[j]);
						}

						results[i] = new BrowseResult(status, contPoint, refDescs);
					}

					if (!succeeded)
					{
						return StatusCode.BadDecodingError;
					}

					if (numRecv != contPoints.Count)
					{
						return StatusCode.GoodResultsMayBeIncomplete;
					}
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode HistoryRead(object historyReadDetails, TimestampsToReturn timestampsToReturn, bool releaseContinuationPoints, HistoryReadValueId[] requests, out HistoryReadResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.HistoryReadRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				if (historyReadDetails is ReadRawModifiedDetails)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadRawModifiedDetails_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);
					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.Encode((historyReadDetails as ReadRawModifiedDetails).IsReadModified);
					succeeded &= sendBuf.Encode((Int64)(historyReadDetails as ReadRawModifiedDetails).StartTime.ToFileTime());
					succeeded &= sendBuf.Encode((Int64)(historyReadDetails as ReadRawModifiedDetails).EndTime.ToFileTime());
					succeeded &= sendBuf.Encode((UInt32)(historyReadDetails as ReadRawModifiedDetails).NumValuesPerNode);
					succeeded &= sendBuf.Encode((historyReadDetails as ReadRawModifiedDetails).ReturnBounds);

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else if (historyReadDetails is ReadProcessedDetails)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadProcessedDetails_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);
					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.Encode((historyReadDetails as ReadProcessedDetails).StartTime.ToFileTime());
					succeeded &= sendBuf.Encode((historyReadDetails as ReadProcessedDetails).EndTime.ToFileTime());
					succeeded &= sendBuf.Encode((historyReadDetails as ReadProcessedDetails).ProcessingInterval);

					succeeded &= sendBuf.Encode((UInt32)(historyReadDetails as ReadProcessedDetails).AggregateTypes.Length);
					for (int i = 0; i < (historyReadDetails as ReadProcessedDetails).AggregateTypes.Length; i++)
					{
						succeeded &= sendBuf.Encode((historyReadDetails as ReadProcessedDetails).AggregateTypes[i]);
					}

					succeeded &= sendBuf.Encode((historyReadDetails as ReadProcessedDetails).Configuration);

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else if (historyReadDetails is ReadAtTimeDetails)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadAtTimeDetails_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);
					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.Encode((historyReadDetails as ReadAtTimeDetails).ReqTimes.Length);
					for (int i = 0; i < (historyReadDetails as ReadAtTimeDetails).ReqTimes.Length; i++)
					{
						succeeded &= sendBuf.Encode((historyReadDetails as ReadAtTimeDetails).ReqTimes[i].ToFileTime());
					}

					succeeded &= sendBuf.Encode((historyReadDetails as ReadAtTimeDetails).UseSimpleBounds);

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else if (historyReadDetails is ReadEventDetails)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadEventDetails_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);
					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.Encode((historyReadDetails as ReadEventDetails).NumValuesPerNode);
					succeeded &= sendBuf.Encode((historyReadDetails as ReadEventDetails).StartTime.ToFileTime());
					succeeded &= sendBuf.Encode((historyReadDetails as ReadEventDetails).EndTime.ToFileTime());
					succeeded &= sendBuf.Encode(new EventFilter((historyReadDetails as ReadEventDetails).SelectClauses, null), false);

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}
				else
				{
					throw new Exception(string.Format("History read details of type {0} is not supported", historyReadDetails.GetType().ToString()));
				}

				succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);
				succeeded &= sendBuf.Encode(releaseContinuationPoints);
				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i].NodeId);
					succeeded &= sendBuf.EncodeUAString(requests[i].IndexRange);
					succeeded &= sendBuf.Encode(requests[i].DataEncoding);
					succeeded &= sendBuf.EncodeUAByteString(requests[i].ContinuationPoint);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.HistoryReadResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				if (!releaseContinuationPoints)
				{
					UInt32 numRecv;
					succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

					results = new HistoryReadResult[numRecv];
					for (int i = 0; i < numRecv && succeeded; i++)
					{
						UInt32 status;
						byte[] contPoint;

						NodeId type;
						byte eoBodyMask;
						UInt32 eoSize;

						succeeded &= recvHandler.RecvBuf.Decode(out status);
						succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out contPoint);
						succeeded &= recvHandler.RecvBuf.Decode(out type);
						succeeded &= recvHandler.RecvBuf.Decode(out eoBodyMask);
						if (eoBodyMask != 1)
						{
							return StatusCode.BadDataEncodingInvalid;
						}
						succeeded &= recvHandler.RecvBuf.Decode(out eoSize);

						if (type.EqualsNumeric(0, (uint)UAConst.HistoryData_Encoding_DefaultBinary))
						{
							UInt32 numDvs;
							succeeded &= recvHandler.RecvBuf.Decode(out numDvs);
							DataValue[] dvs = new DataValue[numDvs];
							for (int j = 0; j < numDvs; j++)
							{
								succeeded &= recvHandler.RecvBuf.Decode(out dvs[j]);
							}

							results[i] = new HistoryReadResult(status, contPoint, dvs);
						}
						else if (type.EqualsNumeric(0, (uint)UAConst.HistoryEvent_Encoding_DefaultBinary))
						{
							UInt32 numDvs;
							succeeded &= recvHandler.RecvBuf.Decode(out numDvs);

							DataValue[] dvs = new DataValue[numDvs];
							for (int j = 0; succeeded && j < numDvs; j++)
							{
								UInt32 numFields;
								succeeded &= recvHandler.RecvBuf.Decode(out numFields);
								object[] fields = new object[numFields];
								for (int k = 0; succeeded && k < numFields; k++)
								{
									succeeded &= recvHandler.RecvBuf.VariantDecode(out fields[k]);
								}

								dvs[j] = new DataValue(fields);
							}

							results[i] = new HistoryReadResult(status, contPoint, dvs);
						}
						else
						{
							return StatusCode.BadDataEncodingInvalid;
						}
					}

					if (!succeeded)
					{
						return StatusCode.BadDecodingError;
					}

					if (numRecv != requests.Length)
					{
						return StatusCode.GoodResultsMayBeIncomplete;
					}
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode HistoryUpdate(HistoryUpdateData[] requests, out uint[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.HistoryUpdateRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(new NodeId(UAConst.UpdateDataDetails_Encoding_DefaultBinary));
					succeeded &= sendBuf.Encode((byte)1);
					int eoStartPos = sendBuf.Position;
					succeeded &= sendBuf.Encode((UInt32)0);

					succeeded &= sendBuf.Encode(requests[i].NodeId);
					succeeded &= sendBuf.Encode((UInt32)requests[i].PerformUpdate);
					succeeded &= sendBuf.Encode((UInt32)requests[i].Value.Length);

					for (int j = 0; j < requests[i].Value.Length; j++)
					{
						succeeded &= sendBuf.Encode(requests[i].Value[j]);
					}

					succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.HistoryUpdateResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new uint[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (numRecv != requests.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode TranslateBrowsePathsToNodeIds(BrowsePath[] requests, out BrowsePathResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.TranslateBrowsePathsToNodeIdsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.TranslateBrowsePathsToNodeIdsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new BrowsePathResult[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (numRecv != requests.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode Call(CallMethodRequest[] requests, out CallMethodResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.CallRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i].ObjectId);
					succeeded &= sendBuf.Encode(requests[i].MethodId);
					succeeded &= sendBuf.Encode((UInt32)requests[i].InputArguments.Length);
					for (int j = 0; j < requests[i].InputArguments.Length; j++)
					{
						succeeded &= sendBuf.VariantEncode(requests[i].InputArguments[j]);
					}
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CallResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numRecv;
				succeeded &= recvHandler.RecvBuf.Decode(out numRecv);

				results = new CallMethodResult[numRecv];
				for (int i = 0; i < numRecv && succeeded; i++)
				{
					UInt32 status;
					UInt32 numResults;
					UInt32[] resultStatus;
					UInt32 numDiagnosticInfos;
					UInt32 numOutputs;
					object[] outputs;

					succeeded &= recvHandler.RecvBuf.Decode(out status);

					succeeded &= recvHandler.RecvBuf.Decode(out numResults);
					resultStatus = new UInt32[numResults];
					for (int j = 0; j < numResults; j++)
					{
						succeeded &= recvHandler.RecvBuf.Decode(out resultStatus[j]);
					}

					succeeded &= recvHandler.RecvBuf.Decode(out numDiagnosticInfos);
					if (numDiagnosticInfos > 0)
					{
						return StatusCode.BadTypeMismatch;
					}

					succeeded &= recvHandler.RecvBuf.Decode(out numOutputs);
					outputs = new object[numOutputs];
					for (int j = 0; j < numResults; j++)
					{
						succeeded &= recvHandler.RecvBuf.VariantDecode(out outputs[j]);
					}

					results[i] = new CallMethodResult(status, resultStatus, outputs);
				}

				if (numRecv != requests.Length)
				{
					return StatusCode.GoodResultsMayBeIncomplete;
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode CreateSubscription(double RequestedPublishingInterval, UInt32 MaxNotificationsPerPublish, bool PublishingEnabled, byte Priority, out uint result)
		{
			result = 0xFFFFFFFFu;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateSubscriptionRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode(RequestedPublishingInterval);
				succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
				succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
				succeeded &= sendBuf.Encode(MaxNotificationsPerPublish);
				succeeded &= sendBuf.Encode(PublishingEnabled);
				succeeded &= sendBuf.Encode(Priority);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateSubscriptionResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				succeeded &= recvHandler.RecvBuf.Decode(out result);

				double revisedPublishInterval;
				UInt32 revisedLifetimeCount;
				UInt32 revisedMaxKeepAliveCount;
				succeeded &= recvHandler.RecvBuf.Decode(out revisedPublishInterval);
				succeeded &= recvHandler.RecvBuf.Decode(out revisedLifetimeCount);
				succeeded &= recvHandler.RecvBuf.Decode(out revisedMaxKeepAliveCount);

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}

			lock (publishReqs)
			{
				if (publishReqs.Count > 0)
				{
					return StatusCode.Good;
				}
			}

			return PublishRequest();
		}

		public StatusCode ModifySubscription(uint subscriptionId, double RequestedPublishingInterval, UInt32 MaxNotificationsPerPublish, bool PublishingEnabled, byte Priority, out uint result)
		{
			result = 0;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.ModifySubscriptionRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode(subscriptionId);

				succeeded &= sendBuf.Encode(RequestedPublishingInterval);
				succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
				succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
				succeeded &= sendBuf.Encode(MaxNotificationsPerPublish);
				succeeded &= sendBuf.Encode(PublishingEnabled);
				succeeded &= sendBuf.Encode(Priority);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ModifySubscriptionResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				double revisedPublishInterval;
				UInt32 revisedLifetimeCount;
				UInt32 revisedMaxKeepAliveCount;
				succeeded &= recvHandler.RecvBuf.Decode(out revisedPublishInterval);
				succeeded &= recvHandler.RecvBuf.Decode(out revisedLifetimeCount);
				succeeded &= recvHandler.RecvBuf.Decode(out revisedMaxKeepAliveCount);

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				result = recvHandler.Header.ServiceResult;
				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode DeleteSubscription(uint[] subscriptionIds, out uint[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteSubscriptionsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)subscriptionIds.Length);
				for (int i = 0; i < subscriptionIds.Length; i++)
				{
					succeeded &= sendBuf.Encode(subscriptionIds[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteSubscriptionsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numResults;
				succeeded &= recvHandler.RecvBuf.Decode(out numResults);
				results = new uint[numResults];
				for (int i = 0; i < numResults; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode SetPublishingMode(bool PublishingEnabled, uint[] requestIds, out uint[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.SetPublishingModeRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode(PublishingEnabled);
				succeeded &= sendBuf.Encode((UInt32)requestIds.Length);
				for (int i = 0; i < requestIds.Length; i++)
				{
					succeeded &= sendBuf.Encode((UInt32)requestIds[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.SetPublishingModeResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numResults;
				succeeded &= recvHandler.RecvBuf.Decode(out numResults);
				results = new uint[numResults];
				for (int i = 0; i < numResults; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode CreateMonitoredItems(uint subscriptionId, TimestampsToReturn timestampsToReturn, MonitoredItemCreateRequest[] requests, out MonitoredItemCreateResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateMonitoredItemsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)subscriptionId);
				succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateMonitoredItemsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numResults;
				succeeded &= recvHandler.RecvBuf.Decode(out numResults);
				results = new MonitoredItemCreateResult[numResults];
				for (int i = 0; i < numResults; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode ModifyMonitoredItems(uint subscriptionId, TimestampsToReturn timestampsToReturn, MonitoredItemModifyRequest[] requests, out MonitoredItemModifyResult[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.ModifyMonitoredItemsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)subscriptionId);
				succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);

				succeeded &= sendBuf.Encode((UInt32)requests.Length);
				for (int i = 0; i < requests.Length; i++)
				{
					succeeded &= sendBuf.Encode(requests[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ModifyMonitoredItemsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numResults;
				succeeded &= recvHandler.RecvBuf.Decode(out numResults);
				results = new MonitoredItemModifyResult[numResults];
				for (int i = 0; i < numResults; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		public StatusCode DeleteMonitoredItems(uint subscriptionId, uint[] monitorIds, out uint[] results)
		{
			results = null;

			try
			{
				cs.WaitOne();
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteMonitoredItemsRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				succeeded &= sendBuf.Encode((UInt32)subscriptionId);
				succeeded &= sendBuf.Encode((UInt32)monitorIds.Length);
				for (int i = 0; i < monitorIds.Length; i++)
				{
					succeeded &= sendBuf.Encode(monitorIds[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
				var recvEv = new ManualResetEvent(false);
				lock (recvNotify)
				{
					recvNotify[recvKey] = recvEv;
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				bool signalled = recvEv.WaitOne(Timeout * 1000);

				lock (recvNotify)
				{
					recvNotify.Remove(recvKey);
				}

				if (!signalled)
				{
					return StatusCode.BadRequestTimeout;
				}

				RecvHandler recvHandler = null;
				lock (recvQueue)
				{
					if (!recvQueue.TryGetValue(recvKey, out recvHandler))
					{
						return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
					}

					recvQueue.Remove(recvKey);
				}

				if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteMonitoredItemsResponse))
				{
					return StatusCode.BadUnknownResponse;
				}

				UInt32 numResults;
				succeeded &= recvHandler.RecvBuf.Decode(out numResults);
				results = new uint[numResults];
				for (int i = 0; i < numResults; i++)
				{
					succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
				}

				if (!succeeded)
				{
					return StatusCode.BadDecodingError;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
				CheckPostCall();
			}
		}

		void ConsumeNotification(RecvHandler recvHandler)
		{
			bool succeeded = true;

			UInt32 subscrId, numSeqNums, seqNum;
			bool MoreNotifications;

			succeeded &= recvHandler.RecvBuf.Decode(out subscrId);
			// AvailableSequenceNumbers
			succeeded &= recvHandler.RecvBuf.Decode(out numSeqNums);
			for (int i = 0; i < numSeqNums; i++) { succeeded &= recvHandler.RecvBuf.Decode(out seqNum); }

			succeeded &= recvHandler.RecvBuf.Decode(out MoreNotifications);
			succeeded &= recvHandler.RecvBuf.Decode(out seqNum);

			UInt64 publishTimeTick;
			succeeded &= recvHandler.RecvBuf.Decode(out publishTimeTick);
			DateTimeOffset publishTime;
			try
			{
				publishTime = DateTimeOffset.FromFileTime((long)publishTimeTick);
			}
			catch
			{
				publishTime = DateTimeOffset.MinValue;
			}

			UInt32 numNotificationData;
			succeeded &= recvHandler.RecvBuf.Decode(out numNotificationData);
			for (int i = 0; succeeded && i < numNotificationData; i++)
			{
				NodeId typeId;
				byte bodyType;
				UInt32 eoSize;

				succeeded &= recvHandler.RecvBuf.Decode(out typeId);
				succeeded &= recvHandler.RecvBuf.Decode(out bodyType);
				succeeded &= recvHandler.RecvBuf.Decode(out eoSize);

				if (bodyType != 1)
				{
					break;
				}

				if (typeId.EqualsNumeric(0, (uint)UAConst.DataChangeNotification_Encoding_DefaultBinary))
				{
					UInt32 numDv;
					succeeded &= recvHandler.RecvBuf.Decode(out numDv);

					if (numDv > 0)
					{
						DataValue[] notifications = new DataValue[numDv];
						uint[] clientHandles = new uint[numDv];
						for (int j = 0; succeeded && j < numDv; j++)
						{
							succeeded &= recvHandler.RecvBuf.Decode(out clientHandles[j]);
							succeeded &= recvHandler.RecvBuf.Decode(out notifications[j]);
						}

						if (!succeeded)
						{
							break;
						}

						NotifyDataChangeNotifications(subscrId, clientHandles, notifications);
					}
				}
				else if (typeId.EqualsNumeric(0, (uint)UAConst.EventNotificationList_Encoding_DefaultBinary))
				{
					UInt32 numDv;
					succeeded &= recvHandler.RecvBuf.Decode(out numDv);

					if (numDv > 0)
					{
						object[][] notifications = new object[numDv][];
						uint[] clientHandles = new uint[numDv];
						for (int j = 0; succeeded && j < numDv; j++)
						{
							succeeded &= recvHandler.RecvBuf.Decode(out clientHandles[j]);

							UInt32 numFields;
							succeeded &= recvHandler.RecvBuf.Decode(out numFields);
							notifications[j] = new object[numFields];
							for (int k = 0; succeeded && k < numFields; k++)
							{
								succeeded &= recvHandler.RecvBuf.VariantDecode(out notifications[j][k]);
							}
						}

						if (!succeeded)
						{
							break;
						}

						NotifyEventNotifications(subscrId, clientHandles, notifications);
					}
				}
				else
				{
					break;
				}
			}

			//results = new uint[numResults];
			//for (int i = 0; i < numResults; i++)
			//{
			//	succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
			//}
		}

		public virtual void NotifyEventNotifications(uint subscrId, uint[] clientHandles, object[][] notifications)
		{
		}

		public virtual void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
		{
		}

		StatusCode PublishRequest()
		{
			if (!cs.WaitOne(0))
			{
				return StatusCode.GoodCallAgain;
			}

			try
			{
				var sendBuf = new MemoryBuffer(MaximumMessageSize);
				var headerRes = EncodeMessageHeader(sendBuf, false);
				if (headerRes != StatusCode.Good)
				{
					return headerRes;
				}

				var reqHeader = new RequestHeader()
				{
					RequestHandle = nextRequestHandle++,
					Timestamp = DateTime.Now,
					AuthToken = config.AuthToken,
				};

				bool succeeded = true;
				succeeded &= sendBuf.Encode(new NodeId(RequestCode.PublishRequest));
				succeeded &= sendBuf.Encode(reqHeader);

				// SubscriptionAcknowledgements
				succeeded &= sendBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return StatusCode.BadEncodingLimitsExceeded;
				}

				lock (publishReqs)
				{
					publishReqs.Add(reqHeader.RequestHandle);
				}

				var sendRes = MessageSecureAndSend(config, sendBuf);
				if (sendRes != StatusCode.Good)
				{
					return sendRes;
				}

				return StatusCode.Good;
			}
			finally
			{
				cs.Release();
			}
		}
	}
}
