using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using LibUA.Core;

namespace LibUA
{
	namespace Server
	{
		public class NetDispatcher : NetDispatcherBase
		{
			protected string LoggerID()
			{
				if (config.Session == null)
				{
					return config.Endpoint.ToString();
				}

				return string.Format("{0}:{1}", config.Endpoint.ToString(), config.Session.ToString());
			}

			public NetDispatcher(Master server, Application app, Socket socket, ILogger logger)
				: base(server, app, socket, logger)
			{
				// Initialize then start consumer
				thread.Start(this);
			}

			protected override bool NeedsPulse()
			{
				if (pendingNotificationRequests.Count == 0)
				{
					return false;
				}

				if (config == null || config.SLState != ConnectionState.Established)
				{
					return false;
				}

				return GetNextPendingSubscription() != null;
			}

			protected override bool Pulse()
			{
				var res = SLPulse();
				if (res != StatusCode.Good)
				{
					UAStatusCode = (uint)res;
				}

				return true;
			}

			StatusCode SLPulse()
			{
				if (config.SLState != ConnectionState.Established ||
					pendingNotificationRequests.Count == 0)
				{
					return StatusCode.BadNothingToDo;
				}

				var sub = GetNextPendingSubscription();
				if (sub == null)
				{
					return StatusCode.BadNothingToDo;
				}

				int numDataPending = 0, numEventPending = 0;
				if (sub.ChangeNotification != Subscription.ChangeNotificationType.None)
				{
					foreach (var mi in sub.MonitoredItems.Values)
					{
						numDataPending += mi.QueueData.Count;
						numEventPending += mi.QueueEvent.Count;
					}
				}

				if (numEventPending > 0)
				{
					return SLPulseEventNotification(sub);
				}

				// Includes keep-alive handler
				return SLPulseDataChangeNotification(sub);
			}

			protected StatusCode SLPulseEventNotification(Subscription sub)
			{
				if (sub.ChangeNotification == Subscription.ChangeNotificationType.None)
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: No updates in SLPulseDataChangeNotification, sub {1}", LoggerID(), sub.SubscriptionId));
					}

					return StatusCode.BadNothingToDo;
				}

				var req = pendingNotificationRequests.Dequeue();
				req.Timestamp = DateTime.Now;

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.PublishResponse, req, (uint)StatusCode.Good);

				bool moreNotifications = false;
				var publishTable = new Dictionary<uint, List<object[]>>();
				int numPublishTableEntries = 0;

				Queue<uint> acknowledgeSeqNums;
				if (!pendingSubscriptionAcknowledgements.TryGetValue(sub.SubscriptionId, out acknowledgeSeqNums))
				{
					acknowledgeSeqNums = new Queue<uint>();
				}

				int numSubAcks = (int)Math.Min(MaxSubscriptionAcknowledgementsPerPublish, acknowledgeSeqNums.Count);

				int availableSpaceLeft = (int)(config.TL.RemoteConfig.MaxMessageSize * UsableMessageSizeFactor) - respBuf.Position;
				availableSpaceLeft -= numSubAcks;

				foreach (var mi in sub.MonitoredItems.Values)
				{
					if (mi.QueueEvent.Count == 0)
					{
						continue;
					}

					var evs = new List<object[]>();

					EventNotification ev;
					while (mi.QueueEvent.TryPeek(out ev))
					{
						var fields = MatchFilterClauses(mi.FilterSelectClauses, ev);

						int sizeRequired = 4 + 4;
						for (int i = 0; i < fields.Length; i++)
						{
							sizeRequired += respBuf.VariantCodingSize(fields[i]);
						}

						// ClientHandle + numEventFields + ev
						if (availableSpaceLeft < sizeRequired)
						{
							moreNotifications = true;
							break;
						}

						availableSpaceLeft -= sizeRequired;
						evs.Add(fields);

						mi.QueueEvent.TryDequeue(out ev);
						++numPublishTableEntries;
					}

					publishTable.Add(mi.Parameters.ClientHandle, evs);
				}

				succeeded &= respBuf.Encode((UInt32)sub.SubscriptionId);

				// Available sequence numbers
				succeeded &= respBuf.Encode((UInt32)1);
				succeeded &= respBuf.Encode((UInt32)sub.SequenceNumber);

				succeeded &= respBuf.Encode(moreNotifications);

				succeeded &= respBuf.Encode((UInt32)sub.SequenceNumber++);
				succeeded &= respBuf.Encode(req.Timestamp.ToFileTimeUtc());

				// One NotificationData
				succeeded &= respBuf.Encode(1);

				succeeded &= respBuf.Encode(new NodeId(UAConst.EventNotificationList_Encoding_DefaultBinary));
				// Body is byte string
				succeeded &= respBuf.Encode((byte)1);

				int dcnSizePosition = respBuf.Position;
				succeeded &= respBuf.Encode((UInt32)0);

				// MonitoredItems
				succeeded &= respBuf.Encode((UInt32)numPublishTableEntries);
				foreach (var kvp in publishTable)
				{
					foreach (var curFields in kvp.Value)
					{
						// ClientHandle
						succeeded &= respBuf.Encode((UInt32)kvp.Key);
						// NumEventFields
						succeeded &= respBuf.Encode((UInt32)curFields.Length);
						for (int i = 0; i < curFields.Length; i++)
						{
							succeeded &= respBuf.VariantEncode(curFields[i]);
						}
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode((UInt32)(respBuf.Position - dcnSizePosition - 4), dcnSizePosition);

				// Results
				succeeded &= respBuf.Encode((UInt32)numSubAcks);
				while (succeeded && numSubAcks-- > 0)
				{
					succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
					acknowledgeSeqNums.Dequeue();
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return StatusCode.BadEncodingError;
				}

				sub.PublishPreviousTime = req.Timestamp;
				sub.ChangeNotification = moreNotifications ?
					Subscription.ChangeNotificationType.Immediate :
					Subscription.ChangeNotificationType.None;

				DispatchMessage_SecureAndSend(config, respBuf);
				return StatusCode.Good;
			}

			public static object[] MatchFilterClauses(SimpleAttributeOperand[] FilterSelectClauses, EventNotification ev)
			{
				object[] fields = null;

				if (FilterSelectClauses != null)
				{
					fields = new object[FilterSelectClauses.Length];
					for (int i = 0; i < FilterSelectClauses.Length; i++)
					{
						var clause = FilterSelectClauses[i];

						bool matchedSelect = false;
						for (int j = 0; j < ev.Fields.Length; j++)
						{
							if (MatchQualifiedNamePath(clause, ev.Fields[j].Operand.BrowsePath))
							{
								matchedSelect = true;
								fields[i] = ev.Fields[j].Value;
								break;
							}
						}

						if (!matchedSelect &&
							clause.AttributeId == NodeAttribute.NodeId)
						{
							for (int j = 0; j < ev.Fields.Length; j++)
							{
								if (clause.AttributeId == ev.Fields[j].Operand.AttributeId)
								{
									matchedSelect = true;
									fields[i] = ev.Fields[j].Value;
									break;
								}
							}
						}

						if (!matchedSelect)
						{
							fields[i] = new object();
						}
					}
				}

				return fields;
			}

			private static bool MatchQualifiedNamePath(SimpleAttributeOperand operand, QualifiedName[] browsePath)
			{
				if ((operand.BrowsePath == null || operand.BrowsePath.Length == 0) &&
					(browsePath == null || browsePath.Length == 0))
				{
					return true;
				}

				if (operand.BrowsePath == null || browsePath == null)
				{
					return false;
				}

				if (operand.BrowsePath.Length != browsePath.Length)
				{
					return false;
				}

				for (int i = 0; i < browsePath.Length; i++)
				{
					if (!operand.BrowsePath[i].Equals(browsePath[i]))
					{
						return false;
					}
				}

				return true;
			}

			protected StatusCode SLPulseDataChangeNotification(Subscription sub)
			{
				var req = pendingNotificationRequests.Dequeue();
				req.Timestamp = DateTime.Now;

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.PublishResponse, req, (uint)StatusCode.Good);

				bool moreNotifications = false;
				var publishTable = new Dictionary<uint, List<DataValue>>();
				int numPublishTableEntries = 0;

				Queue<uint> acknowledgeSeqNums;
				if (!pendingSubscriptionAcknowledgements.TryGetValue(sub.SubscriptionId, out acknowledgeSeqNums))
				{
					acknowledgeSeqNums = new Queue<uint>();
				}

				int numSubAcks = (int)Math.Min(MaxSubscriptionAcknowledgementsPerPublish, acknowledgeSeqNums.Count);

				int availableSpaceLeft = (int)(config.TL.RemoteConfig.MaxMessageSize * UsableMessageSizeFactor) - respBuf.Position;
				availableSpaceLeft -= numSubAcks;

				foreach (var mi in sub.MonitoredItems.Values)
				{
					if (mi.QueueData.Count == 0)
					{
						continue;
					}

					var dvs = new List<DataValue>();

					DataValue dv;
					while (mi.QueueData.TryPeek(out dv))
					{
						// ClientHandle + dv
						int sizeRequired = 4 + respBuf.CodingSize(dv);
						if (availableSpaceLeft < sizeRequired)
						{
							moreNotifications = true;
							break;
						}

						availableSpaceLeft -= sizeRequired;

						dv.ServerTimestamp = req.Timestamp;
						dvs.Add(dv);

						mi.QueueData.TryDequeue(out dv);
						++numPublishTableEntries;
					}

					publishTable.Add(mi.Parameters.ClientHandle, dvs);
				}

				succeeded &= respBuf.Encode((UInt32)sub.SubscriptionId);

				// Available sequence numbers
				succeeded &= respBuf.Encode((UInt32)1);
				succeeded &= respBuf.Encode((UInt32)sub.SequenceNumber);

				succeeded &= respBuf.Encode(moreNotifications);

				succeeded &= respBuf.Encode((UInt32)sub.SequenceNumber++);
				succeeded &= respBuf.Encode(req.Timestamp.ToFileTimeUtc());

				// One NotificationData
				succeeded &= respBuf.Encode(1);

				succeeded &= respBuf.Encode(new NodeId(UAConst.DataChangeNotification_Encoding_DefaultBinary));
				// Body is byte string
				succeeded &= respBuf.Encode((byte)1);

				int dcnSizePosition = respBuf.Position;
				succeeded &= respBuf.Encode((UInt32)0);

				// MonitoredItems
				succeeded &= respBuf.Encode((UInt32)numPublishTableEntries);
				foreach (var kvp in publishTable)
				{
					foreach (var dv in kvp.Value)
					{
						// ClientHandle
						succeeded &= respBuf.Encode((UInt32)kvp.Key);
						succeeded &= respBuf.Encode(dv);
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode((UInt32)(respBuf.Position - dcnSizePosition - 4), dcnSizePosition);

				// Results
				succeeded &= respBuf.Encode((UInt32)numSubAcks);
				while (succeeded && numSubAcks-- > 0)
				{
					succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
					acknowledgeSeqNums.Dequeue();
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return StatusCode.BadEncodingError;
				}

				sub.PublishPreviousTime = req.Timestamp;
				sub.ChangeNotification = moreNotifications ?
					Subscription.ChangeNotificationType.Immediate :
					Subscription.ChangeNotificationType.None;

				DispatchMessage_SecureAndSend(config, respBuf);
				return StatusCode.Good;
			}

			public Subscription GetNextPendingSubscription()
			{
				var now = DateTime.Now;
				TimeSpan largestDelay = TimeSpan.Zero;
				Subscription late = null;

				foreach (var s in subscriptionMap.Values)
				{
					if (!s.PublishingEnabled)
					{
						continue;
					}

					TimeSpan interval = TimeSpan.Zero;

					if (s.ChangeNotification == Subscription.ChangeNotificationType.AtPublish)
					{
						interval = s.PublishInterval;
					}
					else if (s.ChangeNotification == Subscription.ChangeNotificationType.None)
					{
						interval = s.PublishKeepAliveInterval;
					}
					else if (s.ChangeNotification == Subscription.ChangeNotificationType.Immediate)
					{
						return s;
					}

					if (s.PublishPreviousTime == DateTime.MinValue)
					{
						return s;
					}

					TimeSpan delay = now - s.PublishPreviousTime;
					if (delay < interval)
					{
						continue;
					}
					delay -= interval;

					if (delay > largestDelay)
					{
						late = s;
						largestDelay = delay;
					}
				}

				return late;
			}

			protected override int Consume(MemoryBuffer recvBuf)
			{
				// No message type and size
				if (recvBuf.Capacity < 8)
				{
					return 0;
				}

				uint messageType = (uint)recvBuf.Buffer[0] | (uint)(recvBuf.Buffer[1] << 8) | (uint)(recvBuf.Buffer[2] << 16);

				// Check if the whole chunk is here
				if (recvBuf.Buffer[3] == 'F')
				{
					uint messageSize =
							(uint)recvBuf.Buffer[4] | (uint)(recvBuf.Buffer[5] << 8) |
							(uint)(recvBuf.Buffer[6] << 16) | (uint)(recvBuf.Buffer[7] << 24);

					if (config != null && config.TL != null &&
						messageSize > config.TL.LocalConfig.MaxMessageSize)
					{
						UAStatusCode = (uint)StatusCode.BadResponseTooLarge;
						return ErrorInternal;
					}

					if (messageSize > recvBuf.Capacity)
					{
						return 0;
					}

					if (messageType == (uint)MessageType.Message || messageType == (uint)MessageType.Close)
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
								UAStatusCode = unsecureRes;
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

					int restorePos = recvBuf.Position;
					if (config.MessageSecurityMode > MessageSecurityMode.None &&
						config.LocalKeysets != null && config.RemoteKeysets != null)
					{
						recvBuf = ChunkReconstructSecured(recvBuf, chunkSizes, config);
						if (recvBuf == null)
						{
							UAStatusCode = (uint)StatusCode.BadMessageNotAvailable;
							return ErrorInternal;
						}
					}
					else
					{
						if (!ChunkReconstruct(recvBuf, chunkSizes))
						{
							UAStatusCode = (uint)StatusCode.BadMessageNotAvailable;
							return ErrorInternal;
						}
					}

					recvBuf.Position = restorePos;

					uint messageSize = 0;
					foreach (var chunkSize in chunkSizes) { messageSize += chunkSize; }
					MarkPositionAsSize(recvBuf, messageSize);
				}
				else
				{
					UAStatusCode = (uint)StatusCode.BadMessageNotAvailable;
					return ErrorInternal;
				}

				recvBuf.Position += 3;

				if (messageType == (uint)MessageType.Hello)
				{
					if (config.TL == null)
					{
						return DispatchHello(config, recvBuf);
					}

					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: TL already set", LoggerID()));
					}

					return ErrorInternal;
				}
				else if (messageType == (uint)MessageType.Open)
				{
					if (config.TL == null)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Message type 0x{1} is not supported before Hello", LoggerID(), messageType.ToString("X")));
							return ErrorInternal;
						}
					}

					return DispatchOpen(config, recvBuf);
				}
				else if (messageType == (uint)MessageType.Message ||
					messageType == (uint)MessageType.Close)
				{
					if (config.TL == null)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Message type 0x{1} is not supported before Hello", LoggerID(), messageType.ToString("X")));
							UAStatusCode = (uint)StatusCode.BadTcpMessageTypeInvalid;
							return ErrorInternal;
						}
					}

					if (config.SecurityPolicy == SecurityPolicy.Invalid)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Message type 0x{1} is not supported before SecurityPolicy is set", LoggerID(), messageType.ToString("X")));
							UAStatusCode = (uint)StatusCode.BadSecureChannelTokenUnknown;
							return ErrorInternal;
						}
					}

					return DispatchMessage(config, recvBuf);
				}

				if (logger != null)
				{
					logger.Log(LogLevel.Error, string.Format("{0}: Message type 0x{1} is not supported", LoggerID(), messageType.ToString("X")));
				}

				UAStatusCode = (uint)StatusCode.BadTcpMessageTypeInvalid;
				return ErrorInternal;
			}

			protected int DispatchMessage(SLChannel config, MemoryBuffer recvBuf)
			{
				if (recvBuf.Buffer[recvBuf.Position] != 'F')
				{
					// TODO: Re-assemble chunks
					throw new Exception();
				}

				recvBuf.Position++;

				uint messageSize = 0;
				if (!recvBuf.Decode(out messageSize)) { return ErrorParseFail; }
				if (messageSize > recvBuf.Capacity)
				{
					throw new Exception("Incomplete message");
				}

				UInt32 secureChannelId, securityTokenId, securitySeqNum, securityReqId;
				if (!recvBuf.Decode(out secureChannelId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out securityTokenId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out securitySeqNum)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out securityReqId)) { return ErrorParseFail; }

				if (secureChannelId != config.ChannelID &&
					(!config.PrevChannelID.HasValue || secureChannelId != config.PrevChannelID.Value))
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Requested secure channel ID {1} but current is {2} and previous was {3}", LoggerID(), secureChannelId, config.ChannelID, config.PrevChannelID.HasValue ? config.PrevChannelID.ToString() : "null"));
					}

					UAStatusCode = (uint)StatusCode.BadSecureChannelIdInvalid;
					return ErrorInternal;
				}

				//Console.WriteLine("Recv token {0} prev {1}", config.TokenID, config.PrevTokenID.HasValue ? config.PrevTokenID.ToString() : "null");

				if (securityTokenId != config.TokenID &&
					(!config.PrevTokenID.HasValue || securityTokenId != config.PrevTokenID.Value))
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Requested security token ID {1} but current is {2} and previous was {3}", LoggerID(), securityTokenId, config.TokenID, config.PrevTokenID.HasValue ? config.PrevTokenID.ToString() : "null"));
					}

					UAStatusCode = (uint)StatusCode.BadIdentityTokenInvalid;
					return ErrorInternal;
				}

				if (config.RemoteSequence.SequenceNumber >= securitySeqNum)
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Sequence number is {1}, expected {2} or higher", LoggerID(), securitySeqNum, config.RemoteSequence.SequenceNumber));
					}

					UAStatusCode = (uint)StatusCode.BadSequenceNumberInvalid;
					return ErrorInternal;
				}

				config.RemoteSequence.SequenceNumber = securitySeqNum;

				NodeId typeId;
				if (!recvBuf.Decode(out typeId)) { return ErrorParseFail; }

				RequestHeader reqHeader;
				if (!recvBuf.Decode(out reqHeader)) { return ErrorParseFail; }
				reqHeader.SecurityTokenID = config.TokenID;
				reqHeader.SecurityRequestID = securityReqId;
				reqHeader.SecuritySequenceNum = securitySeqNum;

				if (config.AuthToken != null && !reqHeader.AuthToken.Equals(config.AuthToken))
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Bad auth token {1}, expected {2}", LoggerID(), reqHeader.AuthToken.ToString(), config.AuthToken.ToString()));
					}

					UAStatusCode = (uint)StatusCode.BadSecureChannelTokenUnknown;
					return ErrorInternal;
				}

				if (logger != null)
				{
					logger.Log(LogLevel.Info, string.Format("{0}: Message type {1} with SL state {2}", LoggerID(), typeId.ToString(), config.SLState.ToString()));
				}

				if (typeId.NamespaceIndex == 0)
				{
					if (config.SLState == ConnectionState.Established)
					{
						switch (typeId.NumericIdentifier)
						{
							case (uint)RequestCode.FindServersRequest: return DispatchMessage_FindServersRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.GetEndpointsRequest: return DispatchMessage_GetEndpointsRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CreateSessionRequest: return DispatchMessage_CreateSessionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.ActivateSessionRequest: return DispatchMessage_ActivateSessionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.CloseSessionRequest:
								if (logger != null)
								{
									logger.Log(LogLevel.Info, string.Format("{0}: Client sent CloseSessionRequest", LoggerID()));
								}
								return ErrorClosed;

							case (uint)RequestCode.ReadRequest: return DispatchMessage_ReadRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.HistoryReadRequest: return DispatchMessage_HistoryReadRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.WriteRequest: return DispatchMessage_WriteRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.HistoryUpdateRequest: return DispatchMessage_HistoryUpdateRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.BrowseRequest: return DispatchMessage_BrowseRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.BrowseNextRequest: return DispatchMessage_BrowseNextRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.TranslateBrowsePathsToNodeIdsRequest: return DispatchMessage_TranslateBrowsePathsToNodeIdsRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CallRequest: return DispatchMessage_CallRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.RegisterNodesRequest: return DispatchMessage_RegisterNodesRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CreateSubscriptionRequest: return DispatchMessage_CreateSubscriptionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.SetPublishingModeRequest: return DispatchMessage_SetPublishingModeRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.ModifySubscriptionRequest: return DispatchMessage_ModifySubscriptionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.DeleteSubscriptionsRequest: return DispatchMessage_DeleteSubscriptionsRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.TransferSubscriptionsRequest: return DispatchMessage_TransferSubscriptionsRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CreateMonitoredItemsRequest: return DispatchMessage_CreateMonitoredItemsRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.ModifyMonitoredItemsRequest: return DispatchMessage_ModifyMonitoredItemsRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.DeleteMonitoredItemsRequest: return DispatchMessage_DeleteMonitoredItemsRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.SetMonitoringModeRequest: return DispatchMessage_SetMonitoringModeRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.PublishRequest: return DispatchMessage_PublishRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.RepublishRequest: return DispatchMessage_RepublishRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CloseSecureChannelRequest:
								if (logger != null)
								{
									logger.Log(LogLevel.Info, string.Format("{0}: Client sent CloseSecureChannelRequest", LoggerID()));
								}
								return ErrorClosed;
						}
					}
					else
					{
						switch (typeId.NumericIdentifier)
						{
							case (uint)RequestCode.FindServersRequest: return DispatchMessage_FindServersRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.GetEndpointsRequest: return DispatchMessage_GetEndpointsRequest(config, reqHeader, recvBuf, messageSize);

							case (uint)RequestCode.CreateSessionRequest: return DispatchMessage_CreateSessionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.ActivateSessionRequest: return DispatchMessage_ActivateSessionRequest(config, reqHeader, recvBuf, messageSize);
							case (uint)RequestCode.CloseSessionRequest:
								if (logger != null)
								{
									logger.Log(LogLevel.Info, string.Format("{0}: Client sent CloseSessionRequest", LoggerID()));
								}
								return ErrorClosed;

							case (uint)RequestCode.CloseSecureChannelRequest:
								if (logger != null)
								{
									logger.Log(LogLevel.Info, string.Format("{0}: Client sent CloseSecureChannelRequest", LoggerID()));
								}
								return ErrorClosed;

							default:
								break;
						}
					}
				}

				if (logger != null)
				{
					logger.Log(LogLevel.Error, string.Format("{0}: Message type {1} is not supported with SL state {2}", LoggerID(), typeId.ToString(), config.SLState.ToString()));
				}

				UAStatusCode = (uint)StatusCode.BadServiceUnsupported;
				return ErrorInternal;
			}

			protected bool DispatchMessage_WriteHeader(SLChannel config, MemoryBuffer respBuf, uint serviceTypeId, RequestHeader reqHeader, uint serviceResult)
			{
				bool succeeded = true;
				succeeded &= respBuf.Encode((uint)(MessageType.Message) | ((uint)'F' << 24));
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode(config.ChannelID);

				succeeded &= respBuf.Encode(config.TokenID);
				succeeded &= respBuf.Encode(config.LocalSequence.SequenceNumber);
				succeeded &= respBuf.Encode(reqHeader.SecurityRequestID);

				succeeded &= respBuf.Encode(new NodeId(serviceTypeId));

				var respHeader = new ResponseHeader(reqHeader);
				respHeader.ServiceResult = serviceResult;
				succeeded &= respBuf.Encode(respHeader);

				config.LocalSequence.SequenceNumber++;
				return succeeded;
			}

			protected int DispatchMessage_ActivateSessionRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				string clientSignatureAlgorithm;
				byte[] clientSignature;
				string[] localeIds;

				if (!recvBuf.DecodeUAString(out clientSignatureAlgorithm)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out clientSignature)) { return ErrorParseFail; }

				UInt32 numSignedSoftwareCertificate;
				if (!recvBuf.Decode(out numSignedSoftwareCertificate)) { return ErrorParseFail; }
				if (numSignedSoftwareCertificate != 0xFFFFFFFFu)
				{
					for (uint i = 0; i < numSignedSoftwareCertificate; i++)
					{
						string CertificateData;
						byte[] Signature;

						if (!recvBuf.DecodeUAString(out CertificateData)) { return ErrorParseFail; }
						if (!recvBuf.DecodeUAByteString(out Signature)) { return ErrorParseFail; }
					}
				}

				if (!recvBuf.DecodeUAString(out localeIds)) { return ErrorParseFail; }

				NodeId userIdentityTokenTypeId;
				if (!recvBuf.Decode(out userIdentityTokenTypeId)) { return ErrorParseFail; }
				byte userIdentityTokenBodyMask;
				if (!recvBuf.Decode(out userIdentityTokenBodyMask)) { return ErrorParseFail; }

				// Binary body
				if (userIdentityTokenBodyMask != 1)
				{
					return ErrorParseFail;
				}

				if (userIdentityTokenTypeId.NumericIdentifier == (uint)UserIdentityTokenType.Anonymous)
				{
					uint bodySize;
					string policyId;

					if (!recvBuf.Decode(out bodySize)) { return ErrorParseFail; }
					if (!recvBuf.DecodeUAString(out policyId)) { return ErrorParseFail; }

					if (!app.SessionValidateClientUser(config.Session, new UserIdentityAnonymousToken(policyId)))
					{
						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorParseFail;
					}
				}
				else if (userIdentityTokenTypeId.NumericIdentifier == (uint)UserIdentityTokenType.UserNameIdentityToken)
				{
					uint bodySize;
					string policyId, username, algorithm;
					byte[] password;

					if (!recvBuf.Decode(out bodySize)) { return ErrorParseFail; }
					if (!recvBuf.DecodeUAString(out policyId)) { return ErrorParseFail; }
					if (!recvBuf.DecodeUAString(out username)) { return ErrorParseFail; }
					if (!recvBuf.DecodeUAByteString(out password)) { return ErrorParseFail; }
					if (!recvBuf.DecodeUAString(out algorithm)) { return ErrorParseFail; }

					var expectHash = UASecurity.RsaPkcs15Sha_Decrypt(
						new ArraySegment<byte>(password),
						app.ApplicationCertificate, app.ApplicationPrivateKey,
						SecurityPolicy.Basic128Rsa15);

					int passByteLen = expectHash[0] | (expectHash[1] << 8) | (expectHash[2] << 16) | (expectHash[3] << 24);

					if (config.SessionIssuedNonce != null)
					{
						passByteLen -= config.SessionIssuedNonce.Length;
					}

					var passSegment = new ArraySegment<byte>(expectHash, 4, passByteLen);
					if (!app.SessionValidateClientUser(config.Session, new UserIdentityUsernameToken(policyId, username, passSegment.ToArray(), algorithm)))
					{
						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorParseFail;
					}
				}
				else
				{
					UAStatusCode = (uint)StatusCode.BadIdentityTokenInvalid;
					return ErrorParseFail;
				}

				string signatureAlgorithm;
				byte[] signatureByteString;
				if (!recvBuf.DecodeUAString(out signatureAlgorithm)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out signatureByteString)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.ActivateSessionResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				if (config.MessageSecurityMode == MessageSecurityMode.None)
				{
					// Server nonce
					succeeded &= respBuf.EncodeUAByteString(null);
				}
				else
				{
					if (config.SessionIssuedNonce == null)
					{
						UAStatusCode = (uint)StatusCode.BadSessionClosed;
						return ErrorInternal;
					}

					if (clientSignatureAlgorithm != Types.SignatureAlgorithmSha1 &&
						clientSignatureAlgorithm != Types.SignatureAlgorithmSha256)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Client signature algorithm {1} is not supported", LoggerID(), clientSignatureAlgorithm));
						}

						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorInternal;
					}

					var strLocalCert = app.ApplicationCertificate.Export(X509ContentType.Cert);
					var signMsg = new byte[strLocalCert.Length + config.SessionIssuedNonce.Length];
					Array.Copy(strLocalCert, 0, signMsg, 0, strLocalCert.Length);
					Array.Copy(config.SessionIssuedNonce, 0, signMsg, strLocalCert.Length, config.SessionIssuedNonce.Length);

					if (!UASecurity.RsaPkcs15Sha_VerifySigned(new ArraySegment<byte>(signMsg),
						clientSignature, config.RemoteCertificate, config.SecurityPolicy))
					{
						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorInternal;
					}

					config.SessionIssuedNonce = UASecurity.GenerateRandomBytes(UASecurity.ActivationNonceSize);
					// Server nonce
					succeeded &= respBuf.EncodeUAByteString(config.SessionIssuedNonce);
				}

				// Results
				succeeded &= respBuf.Encode((UInt32)0);

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				config.SLState = ConnectionState.Established;
				if (!app.SessionActivateClient(config.Session, config.SecurityPolicy, config.MessageSecurityMode, config.RemoteCertificate))
				{
					UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
					return ErrorParseFail;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_CreateSessionRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				ApplicationDescription clientDesc = null;
				if (!recvBuf.Decode(out clientDesc)) { return ErrorParseFail; }

				string severUri, endpointUrl, sessionName;
				byte[] clientNonce, clientCertificate;
				double requestedSessionTimeOut;
				UInt32 maxResponseMessageSize;

				if (!recvBuf.DecodeUAString(out severUri)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out endpointUrl)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out sessionName)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out clientNonce)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out clientCertificate)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out requestedSessionTimeOut)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out maxResponseMessageSize)) { return ErrorParseFail; }

				if (!app.SessionValidateClientApplication(config.Session, clientDesc, clientCertificate, sessionName))
				{
					UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
					return ErrorInternal;
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.CreateSessionResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var endpointDescs = app.GetEndpointDescriptions(endpointUrl);
				config.AuthToken = new NodeId(1, (ushort)(config.ChannelID ^ config.LocalSequence.SequenceNumber));
				config.SessionIdToken = new NodeId(0, string.Format("S:{0}", config.AuthToken.NumericIdentifier));
				//config.SessionIdToken = new NodeId(0, new byte[16] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, NodeIdNetType.Guid);

				succeeded &= respBuf.Encode(config.SessionIdToken);
				succeeded &= respBuf.Encode(config.AuthToken);
				succeeded &= respBuf.Encode((double)requestedSessionTimeOut);

				if (config.MessageSecurityMode == MessageSecurityMode.None)
				{
					// Server nonce
					succeeded &= respBuf.EncodeUAByteString(null);
					// Server certificate
					succeeded &= respBuf.EncodeUAByteString(null);

					succeeded &= respBuf.Encode((UInt32)endpointDescs.Count);
					for (int i = 0; i < endpointDescs.Count && succeeded; i++)
					{
						succeeded &= respBuf.Encode(endpointDescs[i]);
					}

					// ServerSoftwareCertificates
					succeeded &= respBuf.Encode((UInt32)0xFFFFFFFFu);

					// Server signature algorithm
					succeeded &= respBuf.EncodeUAString((string)null);
					// Server signature
					succeeded &= respBuf.EncodeUAByteString(null);
				}
				else
				{
					var signMsg = new byte[clientCertificate.Length + clientNonce.Length];
					Array.Copy(clientCertificate, 0, signMsg, 0, clientCertificate.Length);
					Array.Copy(clientNonce, 0, signMsg, clientCertificate.Length, clientNonce.Length);

					var serverSignature = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(signMsg),
						app.ApplicationPrivateKey, config.SecurityPolicy);

					// Verify in ActivateSession
					config.SessionIssuedNonce = UASecurity.GenerateRandomBytes(UASecurity.ActivationNonceSize);

					// Server nonce
					succeeded &= respBuf.EncodeUAByteString(config.SessionIssuedNonce);
					// Server certificate
					succeeded &= respBuf.EncodeUAByteString(app.ApplicationCertificate.Export(X509ContentType.Cert));

					succeeded &= respBuf.Encode((UInt32)endpointDescs.Count);
					for (int i = 0; i < endpointDescs.Count && succeeded; i++)
					{
						succeeded &= respBuf.Encode(endpointDescs[i]);
					}

					// ServerSoftwareCertificates
					succeeded &= respBuf.Encode((UInt32)0xFFFFFFFFu);

					// Server signature algorithm
					if (config.SecurityPolicy == SecurityPolicy.Basic256Sha256)
					{
						succeeded &= respBuf.EncodeUAString(Types.SignatureAlgorithmSha256);
					}
					else
					{
						succeeded &= respBuf.EncodeUAString(Types.SignatureAlgorithmSha1);
					}

					// Server signature
					succeeded &= respBuf.EncodeUAByteString(serverSignature);
				}

				maxResponseMessageSize = Math.Min(config.TL.LocalConfig.MaxMessageSize, config.TL.RemoteConfig.MaxMessageSize);
				succeeded &= respBuf.Encode(maxResponseMessageSize);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_FindServersRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				string endpointUrl;
				string[] localeIds, profileIds;

				if (!recvBuf.DecodeUAString(out endpointUrl)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out localeIds)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out profileIds)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.FindServersResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var applicationDesc = app.GetApplicationDescription(endpointUrl);

				if (applicationDesc == null)
				{
					succeeded &= respBuf.Encode((UInt32)0);
				}
				else
				{
					succeeded &= respBuf.Encode((UInt32)1);
					succeeded &= respBuf.Encode(applicationDesc, new string[] { endpointUrl });
				}

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_GetEndpointsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				string endpointUrl;
				string[] localeIds, profileIds;

				if (!recvBuf.DecodeUAString(out endpointUrl)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out localeIds)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAString(out profileIds)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.GetEndpointsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var endpointDescs = app.GetEndpointDescriptions(endpointUrl);

				succeeded &= respBuf.Encode((UInt32)endpointDescs.Count);
				for (int i = 0; i < endpointDescs.Count && succeeded; i++)
				{
					succeeded &= respBuf.Encode(endpointDescs[i]);
				}

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
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

			private void DispatchMessage_SecureAndSend(SLChannel config, MemoryBuffer respBuf)
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
					UAStatusCode = (uint)StatusCode.BadEncodingLimitsExceeded;
					return;
				}

				if (numChunks > 1)
				{
					//Console.WriteLine("{0} -> {1} chunks", respBuf.Position, numChunks);
					//var bigChunkBuffer = new MemoryBuffer((int)config.TL.RemoteConfig.MaxMessageSize);

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

						//MarkPositionAsSize(chunk);
						//bigChunkBuffer.Append(chunk.Buffer, chunk.Position);

						if (config.MessageSecurityMode == MessageSecurityMode.None)
						{
							MarkPositionAsSize(chunk);
						}
						else
						{
							var secureRes = (uint)UASecurity.SecureSymmetric(chunk, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

							if (!Types.StatusCodeIsGood(secureRes))
							{
								UAStatusCode = secureRes;
								return;
							}
						}

						int numSent = socket.Send(chunk.Buffer, chunk.Position, SocketFlags.None);
					}

					//var chunkSizes = ChunkCalculateSizes(bigChunkBuffer);
					//if (chunkSizes != null)
					//{
					//	MarkPositionAsSize(respBuf);
					//	ChunkReconstruct(bigChunkBuffer, chunkSizes);
					//	for (int i = 0; i < respBuf.Position; i++)
					//	{
					//		if (respBuf.Buffer[i] != bigChunkBuffer.Buffer[i])
					//		{
					//			throw new Exception();
					//		}
					//	}
					//}
				}
				else
				{
					if (config.MessageSecurityMode == MessageSecurityMode.None)
					{
						MarkPositionAsSize(respBuf);
					}
					else
					{
						var secureRes = (uint)UASecurity.SecureSymmetric(respBuf, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

						if (!Types.StatusCodeIsGood(secureRes))
						{
							UAStatusCode = secureRes;
							return;
						}
					}

					int numSent = socket.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
				}
			}

			protected int DispatchOpen(SLChannel config, MemoryBuffer recvBuf)
			{
				if (config.SecurityPolicy != SecurityPolicy.None)
				{
					if (app.ApplicationCertificate == null)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Application did not return application certificate, requested security policy {1}", LoggerID(), recvBuf.Buffer[recvBuf.Position].ToString("X")));
						}

						return ErrorInternal;
					}

					if (app.ApplicationPrivateKey == null)
					{
						if (logger != null)
						{
							logger.Log(LogLevel.Error, string.Format("{0}: Application did not return application private key, requested security policy {1}", LoggerID(), recvBuf.Buffer[recvBuf.Position].ToString("X")));
						}

						return ErrorInternal;
					}
				}

				if (recvBuf.Buffer[recvBuf.Position] != 'F')
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Open can only have Final chunk type, not 0x{1}", LoggerID(), recvBuf.Buffer[recvBuf.Position].ToString("X")));
					}
				}

				recvBuf.Position++;

				uint messageSize = 0;
				if (!recvBuf.Decode(out messageSize)) { return ErrorParseFail; }
				if (messageSize > recvBuf.Capacity)
				{
					throw new Exception("Incomplete message");
				}

				UInt32 secureChannelId;
				string securityPolicyUri;
				byte[] senderCertificate, recvCertThumbprint;
				UInt32 sequenceNumber, requestId;
				NodeId messageType;

				if (!recvBuf.Decode(out secureChannelId)) { return ErrorParseFail; }

				// AsymmetricAlgorithmSecurityHeader
				if (!recvBuf.DecodeUAString(out securityPolicyUri)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out senderCertificate)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out recvCertThumbprint)) { return ErrorParseFail; }

				try
				{
					config.MessageSecurityMode = MessageSecurityMode.Invalid;
					if (securityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.None])
					{
						config.SecurityPolicy = SecurityPolicy.None;
					}
					else if (securityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256])
					{
						config.SecurityPolicy = SecurityPolicy.Basic256;
					}
					else if (securityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15])
					{
						config.SecurityPolicy = SecurityPolicy.Basic128Rsa15;
					}
					else if (securityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256])
					{
						config.SecurityPolicy = SecurityPolicy.Basic256Sha256;
					}
					else
					{
						UAStatusCode = (uint)StatusCode.BadSecurityPolicyRejected;
						return ErrorInternal;
					}
				}
				catch
				{
					UAStatusCode = (uint)StatusCode.BadSecurityPolicyRejected;
					return ErrorInternal;
				}

				config.RemoteCertificate = null;

				// Check in the middle for buffer decrypt
				if (config.SecurityPolicy != SecurityPolicy.None)
				{
					try
					{

						config.RemoteCertificate = new X509Certificate2(senderCertificate);
						if (!UASecurity.VerifyCertificate(config.RemoteCertificate))
						{
							UAStatusCode = (uint)StatusCode.BadCertificateInvalid;
							return ErrorInternal;
						}
					}
					catch
					{
						UAStatusCode = (uint)StatusCode.BadCertificateInvalid;
						return ErrorInternal;
					}

					var appCertStr = app.ApplicationCertificate.Export(X509ContentType.Cert);
					if (!UASecurity.SHAVerify(appCertStr, recvCertThumbprint, SecurityPolicy.Basic128Rsa15))
					{
						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorInternal;
					}

					var paddingMethod = UASecurity.PaddingMethodForSecurityPolicy(config.SecurityPolicy);
					var asymDecBuf = UASecurity.RsaPkcs15Sha_Decrypt(
						new ArraySegment<byte>(recvBuf.Buffer, recvBuf.Position, recvBuf.Capacity - recvBuf.Position),
						app.ApplicationCertificate, app.ApplicationPrivateKey, config.SecurityPolicy);

					int minPlainSize = Math.Min(asymDecBuf.Length, recvBuf.Capacity - recvBuf.Position);
					Array.Copy(asymDecBuf, 0, recvBuf.Buffer, recvBuf.Position, minPlainSize);
				}

				if (!recvBuf.Decode(out sequenceNumber)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out requestId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out messageType)) { return ErrorParseFail; }

				if (!messageType.EqualsNumeric(0, (uint)RequestCode.OpenSecureChannelRequest))
				{
					UAStatusCode = (uint)StatusCode.BadSecureChannelClosed;
					return ErrorInternal;
				}

				RequestHeader reqHeader;
				if (!recvBuf.Decode(out reqHeader)) { return ErrorParseFail; }

				UInt32 clientProtocolVersion;
				UInt32 securityTokenRequestType;
				UInt32 messageSecurityMode;
				byte[] clientNonce;
				UInt32 reqLifetime;

				if (!recvBuf.Decode(out clientProtocolVersion)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out securityTokenRequestType)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out messageSecurityMode)) { return ErrorParseFail; }
				if (!recvBuf.DecodeUAByteString(out clientNonce)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out reqLifetime)) { return ErrorParseFail; }

				try
				{
					config.MessageSecurityMode = (MessageSecurityMode)messageSecurityMode;
				}
				catch
				{
					UAStatusCode = (uint)StatusCode.BadSecurityPolicyRejected;
					return ErrorInternal;
				}

				if (securityTokenRequestType == (uint)SecurityTokenRequestType.Issue)
				{
					var rnd = new Random();
					config.ChannelID = 1; //(uint)(rnd.Next() % 10000);
					config.TokenID = 1000;

					config.LocalSequence = new SLSequence()
					{
						SequenceNumber = sequenceNumber,
						RequestId = requestId
					};

					config.RemoteSequence = new SLSequence()
					{
						SequenceNumber = sequenceNumber,
						RequestId = requestId
					};

					if (logger != null)
					{
						logger.Log(LogLevel.Info, string.Format("{0}: SL security token {1} issued for channel {2} with security policy {3}", LoggerID(), config.TokenID, config.ChannelID, config.SecurityPolicy.ToString()));
					}
				}
				else if (securityTokenRequestType == (uint)SecurityTokenRequestType.Renew)
				{
					if (config.SLState != ConnectionState.Established)
					{
						UAStatusCode = (uint)StatusCode.BadIdentityTokenInvalid;
						return ErrorInternal;
					}

					if (config.ChannelID != secureChannelId)
					{
						UAStatusCode = (uint)StatusCode.BadSecureChannelIdInvalid;
						return ErrorInternal;
					}

					config.PrevTokenID = config.TokenID;
					config.TokenID++;

					reqHeader.SecurityTokenID = config.TokenID;

					if (logger != null)
					{
						logger.Log(LogLevel.Info, string.Format("{0}: SL security token {1} renewed for channel {2} with security policy {3}, previous token was {4}", LoggerID(), config.TokenID, config.ChannelID, config.SecurityPolicy.ToString(), config.PrevTokenID.ToString()));
					}

					foreach (var sub in subscriptionMap.Values)
					{
						sub.ChangeNotification = Subscription.ChangeNotificationType.Immediate;
					}
				}
				else
				{
					// TODO: Invalid request type
					throw new Exception();
				}

				config.TokenLifetime = Math.Min(reqLifetime, MaxTokenLifetime);
				config.TokenCreatedAt = reqHeader.Timestamp;

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					config.LocalNonce = new byte[] { 1 };
					config.LocalKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
					config.RemoteKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
				}
				else
				{
					int symKeySize = UASecurity.SymmetricKeySizeForSecurityPolicy(config.SecurityPolicy, clientNonce.Length);

					config.LocalNonce = UASecurity.GenerateRandomBytes(symKeySize);
					config.RemoteNonce = clientNonce;

					int sigKeySize = UASecurity.SymmetricSignatureKeySizeForSecurityPolicy(config.SecurityPolicy);
					int symBlockSize = UASecurity.SymmetricBlockSizeForSecurityPolicy(config.SecurityPolicy);

					var clientHash = UASecurity.PSHA(
						config.LocalNonce,
						config.RemoteNonce,
						sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

					var newRemoteKeyset = new SLChannel.Keyset(
						(new ArraySegment<byte>(clientHash, 0, sigKeySize)).ToArray(),
						(new ArraySegment<byte>(clientHash, sigKeySize, symKeySize)).ToArray(),
						(new ArraySegment<byte>(clientHash, sigKeySize + symKeySize, symBlockSize)).ToArray());

					var serverHash = UASecurity.PSHA(
						config.RemoteNonce,
						config.LocalNonce,
						sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

					var newLocalKeyset = new SLChannel.Keyset(
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

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = true;
				succeeded &= respBuf.Encode((uint)(MessageType.Open) | ((uint)'F' << 24));
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode(config.ChannelID);
				succeeded &= respBuf.EncodeUAString(Types.SLSecurityPolicyUris[(int)config.SecurityPolicy]);

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					// SenderCertificate
					succeeded &= respBuf.EncodeUAByteString(null);
					// RecieverCertificateThumbprint
					succeeded &= respBuf.EncodeUAByteString(null);
				}
				else
				{
					var appCertStr = app.ApplicationCertificate.Export(X509ContentType.Cert);
					var clientCertThumbprint = UASecurity.SHACalculate(config.RemoteCertificate.Export(X509ContentType.Cert), SecurityPolicy.Basic128Rsa15);

					// SenderCertificate
					succeeded &= respBuf.EncodeUAByteString(appCertStr);
					// RecieverCertificateThumbprint
					succeeded &= respBuf.EncodeUAByteString(clientCertThumbprint);
				}

				int encodeFromPosition = respBuf.Position;

				succeeded &= respBuf.Encode(config.LocalSequence.SequenceNumber);
				succeeded &= respBuf.Encode(requestId);

				succeeded &= respBuf.Encode(new NodeId((uint)RequestCode.OpenSecureChannelResponse));

				var respHeader = new ResponseHeader(reqHeader);
				succeeded &= respBuf.Encode(respHeader);
				// ServerProtocolVersion
				succeeded &= respBuf.Encode((UInt32)0);

				succeeded &= respBuf.Encode(config.ChannelID);
				succeeded &= respBuf.Encode(config.TokenID);
				succeeded &= respBuf.Encode((UInt64)config.TokenCreatedAt.ToFileTime());
				succeeded &= respBuf.Encode(config.TokenLifetime);

				succeeded &= respBuf.EncodeUAByteString(config.LocalNonce);

				if (config.SecurityPolicy == SecurityPolicy.None)
				{
					MarkPositionAsSize(respBuf);
				}
				else
				{
					var padMethod = UASecurity.PaddingMethodForSecurityPolicy(config.SecurityPolicy);
					int sigSize = UASecurity.CalculateSignatureSize(app.ApplicationCertificate);
					int padSize = UASecurity.CalculatePaddingSize(config.RemoteCertificate, config.SecurityPolicy, respBuf.Position - encodeFromPosition, sigSize);

					if (padSize > 0)
					{
						byte paddingValue = (byte)((padSize - 1) & 0xFF);

						var appendPadding = new byte[padSize];
						for (int i = 0; i < padSize; i++) { appendPadding[i] = paddingValue; }
						respBuf.Append(appendPadding);
					}

					int respSize = respBuf.Position + sigSize;

					respSize = encodeFromPosition + UASecurity.CalculateEncryptedSize(config.RemoteCertificate, respSize - encodeFromPosition, padMethod);
					MarkPositionAsSize(respBuf, (UInt32)respSize);

					var msgSign = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(respBuf.Buffer, 0, respBuf.Position),
						app.ApplicationPrivateKey, config.SecurityPolicy);

					//Console.WriteLine("AsymSig: {0}", string.Join("", msgSign.Select(v => v.ToString("X2"))));

					respBuf.Append(msgSign);

					var packed = UASecurity.RsaPkcs15Sha_Encrypt(
						new ArraySegment<byte>(respBuf.Buffer, encodeFromPosition, respBuf.Position - encodeFromPosition),
						config.RemoteCertificate, config.SecurityPolicy);

					respBuf.Position = encodeFromPosition;
					respBuf.Append(packed);

					if (respBuf.Position != respSize)
					{
						UAStatusCode = (uint)StatusCode.BadSecurityChecksFailed;
						return ErrorInternal;
					}
				}

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				config.LocalSequence.SequenceNumber++;

				socket.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
				return (int)messageSize;
			}

			protected int DispatchHello(SLChannel config, MemoryBuffer recvBuf)
			{
				uint messageSize = 0;
				if (recvBuf.Buffer[recvBuf.Position] != 'F')
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Hello can only have Final chunk type, not 0x{1}", LoggerID(), recvBuf.Buffer[recvBuf.Position].ToString("X")));
					}
				}

				recvBuf.Position++;
				if (!recvBuf.Decode(out messageSize)) { return ErrorParseFail; }
				if (messageSize > recvBuf.Capacity)
				{
					throw new Exception("Incomplete message");
				}

				config.TL = new TLConnection();
				const uint chunkSize = (1 << 16) - 1;
				config.TL.LocalConfig = new TLConfiguration()
				{
					ProtocolVersion = 0,
					SendBufferSize = chunkSize,
					RecvBufferSize = chunkSize,
					MaxMessageSize = (uint)maximumMessageSize,
					MaxChunkCount = (uint)(maximumMessageSize + (chunkSize - 1)) / chunkSize,
				};

				config.TL.RemoteConfig = new TLConfiguration();
				if (!recvBuf.Decode(out config.TL.RemoteConfig.ProtocolVersion)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out config.TL.RemoteConfig.RecvBufferSize)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out config.TL.RemoteConfig.SendBufferSize)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out config.TL.RemoteConfig.MaxMessageSize)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out config.TL.RemoteConfig.MaxChunkCount)) { return ErrorParseFail; }

				config.TL.LocalConfig.SendBufferSize = Math.Min(config.TL.LocalConfig.SendBufferSize, config.TL.RemoteConfig.RecvBufferSize);
				if (config.TL.RemoteConfig.MaxMessageSize > 0)
				{
					config.TL.LocalConfig.MaxMessageSize = Math.Min(config.TL.LocalConfig.MaxMessageSize, config.TL.RemoteConfig.MaxMessageSize);
				}
				config.TL.RemoteConfig.MaxMessageSize = config.TL.LocalConfig.MaxMessageSize;

				if (maximumMessageSize > config.TL.LocalConfig.MaxMessageSize)
				{
					maximumMessageSize = (int)config.TL.LocalConfig.MaxMessageSize;
				}

				var endpoint = string.Empty;
				if (!recvBuf.DecodeUAString(out endpoint)) { return ErrorParseFail; }
				config.TL.RemoteEndpoint = endpoint;

				//if (recvBuf.Position != messageSize)
				//{
				//	if (logger != null)
				//	{
				//		logger.Log(LogLevel.Error, string.Format("{0}: Hello expected {0} bytes, parsed {1}", messageSize, recvBuf.Position));
				//	}
				//}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = true;
				succeeded &= respBuf.Encode((uint)(MessageType.Acknowledge) | ((uint)'F' << 24));
				succeeded &= respBuf.Encode((UInt32)0);
				succeeded &= respBuf.Encode(config.TL.LocalConfig.ProtocolVersion);
				succeeded &= respBuf.Encode(config.TL.LocalConfig.RecvBufferSize);
				succeeded &= respBuf.Encode(config.TL.LocalConfig.SendBufferSize);
				succeeded &= respBuf.Encode(config.TL.LocalConfig.MaxMessageSize);
				succeeded &= respBuf.Encode(config.TL.LocalConfig.MaxChunkCount);
				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				MarkPositionAsSize(respBuf);

				socket.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
				return (int)messageSize;
			}

			protected int DispatchMessage_HistoryReadRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				NodeId historyReadTypeId;
				byte historyReadTypeMask;
				UInt32 historyReadTypeSize;
				bool releaseContinuationPoints;
				UInt32 timestampsToReturnUint;
				TimestampsToReturn timestampsToReturn;

				if (!recvBuf.Decode(out historyReadTypeId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out historyReadTypeMask)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out historyReadTypeSize)) { return ErrorParseFail; }

				object readDetails = null;
				if (historyReadTypeId.EqualsNumeric(0, (uint)UAConst.ReadRawModifiedDetails_Encoding_DefaultBinary))
				{
					bool IsReadModified;
					DateTime StartTime, EndTime;
					Int64 StartTimeTick, EndTimeTick;
					UInt32 NumValuesPerNode;
					bool ReturnBounds;

					if (!recvBuf.Decode(out IsReadModified)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out StartTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out EndTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out NumValuesPerNode)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out ReturnBounds)) { return ErrorParseFail; }

					try
					{
						StartTime = DateTime.FromFileTimeUtc(StartTimeTick);
					}
					catch
					{
						StartTime = DateTime.MinValue;
					}

					try
					{
						EndTime = DateTime.FromFileTimeUtc(EndTimeTick);
					}
					catch
					{
						EndTime = DateTime.MaxValue;
					}

					readDetails = new ReadRawModifiedDetails(IsReadModified, StartTime, EndTime, NumValuesPerNode, ReturnBounds);
				}
				else if (historyReadTypeId.EqualsNumeric(0, (uint)UAConst.ReadProcessedDetails_Encoding_DefaultBinary))
				{
					DateTime StartTime, EndTime;
					Int64 StartTimeTick, EndTimeTick;
					double ProcessingInterval;
					Int32 NoOfAggregateTypes;
					NodeId[] AggregateTypes;
					AggregateConfiguration AggregateConfig;

					if (!recvBuf.Decode(out StartTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out EndTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out ProcessingInterval)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out NoOfAggregateTypes)) { return ErrorParseFail; }

					AggregateTypes = new NodeId[NoOfAggregateTypes];
					for (uint i = 0; i < NoOfAggregateTypes; i++)
					{
						if (!recvBuf.Decode(out AggregateTypes[i])) { return ErrorParseFail; }
					}

					if (!recvBuf.Decode(out AggregateConfig)) { return ErrorParseFail; }

					try
					{
						StartTime = DateTime.FromFileTimeUtc(StartTimeTick);
					}
					catch
					{
						StartTime = DateTime.MinValue;
					}

					try
					{
						EndTime = DateTime.FromFileTimeUtc(EndTimeTick);
					}
					catch
					{
						EndTime = DateTime.MaxValue;
					}

					readDetails = new ReadProcessedDetails(StartTime, EndTime, ProcessingInterval, AggregateTypes, AggregateConfig);
				}
				else if (historyReadTypeId.EqualsNumeric(0, (uint)UAConst.ReadAtTimeDetails_Encoding_DefaultBinary))
				{
					Int32 NoOfReqTimes;
					DateTime[] ReqTimes;
					bool UseSimpleBounds;

					if (!recvBuf.Decode(out NoOfReqTimes)) { return ErrorParseFail; }

					ReqTimes = new DateTime[NoOfReqTimes];
					for (uint i = 0; i < NoOfReqTimes; i++)
					{
						Int64 timeTick;
						if (!recvBuf.Decode(out timeTick)) { return ErrorParseFail; }

						try
						{
							ReqTimes[i] = DateTime.FromFileTimeUtc(timeTick);
						}
						catch
						{
							ReqTimes[i] = DateTime.MinValue;
						}
					}

					if (!recvBuf.Decode(out UseSimpleBounds)) { return ErrorParseFail; }

					readDetails = new ReadAtTimeDetails(ReqTimes, UseSimpleBounds);
				}
				else if (historyReadTypeId.EqualsNumeric(0, (uint)UAConst.ReadEventDetails_Encoding_DefaultBinary))
				{
					Int64 StartTimeTick, EndTimeTick;
					UInt32 NumValuesPerNode;
					DateTime StartTime, EndTime;
					EventFilter Filter;

					if (!recvBuf.Decode(out NumValuesPerNode)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out StartTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out EndTimeTick)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out Filter, false)) { return ErrorParseFail; }

					try
					{
						StartTime = DateTime.FromFileTimeUtc(StartTimeTick);
					}
					catch
					{
						StartTime = DateTime.MinValue;
					}

					try
					{
						EndTime = DateTime.FromFileTimeUtc(EndTimeTick);
					}
					catch
					{
						EndTime = DateTime.MaxValue;
					}

					readDetails = new ReadEventDetails(StartTime, EndTime, NumValuesPerNode, Filter.SelectClauses);
				}
				else
				{
					readDetails = null;
				}

				if (!recvBuf.Decode(out timestampsToReturnUint)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out releaseContinuationPoints)) { return ErrorParseFail; }

				try
				{
					timestampsToReturn = (TimestampsToReturn)timestampsToReturnUint;
				}
				catch
				{
					return ErrorParseFail;
				}

				UInt32 numNodesToRead;
				if (!recvBuf.Decode(out numNodesToRead)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = true;

				int availableSpacePerRequest = (int)((config.TL.RemoteConfig.MaxMessageSize / Math.Max(1, numNodesToRead)) * UsableMessageSizeFactor) - respBuf.Position - TLPaddingOverhead;

				if (releaseContinuationPoints)
				{
					succeeded = DispatchMessage_WriteHeader(config, respBuf,
						(uint)RequestCode.HistoryReadResponse, reqHeader, (uint)StatusCode.Good);

					for (int i = 0; i < numNodesToRead; i++)
					{
						NodeId nodeId;
						string indexRange;
						QualifiedName dataEncoding;
						byte[] contPoint;

						if (!recvBuf.Decode(out nodeId)) { return ErrorParseFail; }
						if (!recvBuf.DecodeUAString(out indexRange)) { return ErrorParseFail; }
						if (!recvBuf.Decode(out dataEncoding)) { return ErrorParseFail; }
						if (!recvBuf.DecodeUAByteString(out contPoint)) { return ErrorParseFail; }

						// TODO: Free contPoint
					}

					succeeded &= respBuf.Encode((UInt32)0);
				}
				else if (readDetails == null || numNodesToRead > MaxHistoryReadNodes || availableSpacePerRequest < TLPaddingOverhead)
				{
					if (readDetails == null)
					{
						succeeded = DispatchMessage_WriteHeader(config, respBuf,
							(uint)RequestCode.HistoryReadResponse, reqHeader, (uint)StatusCode.BadHistoryOperationUnsupported);
					}
					else
					{
						succeeded = DispatchMessage_WriteHeader(config, respBuf,
							(uint)RequestCode.HistoryReadResponse, reqHeader, (uint)StatusCode.BadTooManyOperations);
					}

					// NumResults
					succeeded &= respBuf.Encode((UInt32)0);
				}
				else
				{
					succeeded = DispatchMessage_WriteHeader(config, respBuf,
						(uint)RequestCode.HistoryReadResponse, reqHeader, (uint)StatusCode.Good);

					// NumResults
					int numResultsPos = respBuf.Position;
					succeeded &= respBuf.Encode((UInt32)0);

					int numNodesWritten = 0;
					var results = new List<DataValue>();
					var resultsEvents = new List<object[]>();
					for (int i = 0; i < numNodesToRead; i++)
					{
						NodeId nodeId;
						string indexRange;
						QualifiedName dataEncoding;
						byte[] contPoint;

						if (!recvBuf.Decode(out nodeId)) { return ErrorParseFail; }
						if (!recvBuf.DecodeUAString(out indexRange)) { return ErrorParseFail; }
						if (!recvBuf.Decode(out dataEncoding)) { return ErrorParseFail; }
						if (!recvBuf.DecodeUAByteString(out contPoint)) { return ErrorParseFail; }

						var nodeToRead = new HistoryReadValueId(nodeId, indexRange, dataEncoding, contPoint);

						ContinuationPointHistory cont = null;
						int contIndex = -1;

						if (contPoint != null)
						{
							try
							{
								contIndex = BitConverter.ToInt32(contPoint, 0);
							}
							catch
							{
								contIndex = -1;
							}

							if (!continuationHistory.TryGetValue(contIndex, out cont))
							{
								cont = null;
							}
						}

						if (cont == null)
						{
							if (availableContinuationPoints.Count == 0)
							{
								succeeded &= respBuf.Encode((UInt32)StatusCode.BadNoContinuationPoints);
								succeeded &= respBuf.EncodeUAByteString(null);

								succeeded &= respBuf.Encode(new NodeId(UAConst.HistoryData_Encoding_DefaultBinary));
								succeeded &= respBuf.Encode((byte)1);

								// EO size
								succeeded &= respBuf.Encode((UInt32)4);

								// Num DV
								succeeded &= respBuf.Encode((UInt32)0);

								numNodesWritten++;
								continue;
							}

							contIndex = availableContinuationPoints.Pop();

							cont = new ContinuationPointHistory(readDetails, timestampsToReturn, nodeToRead)
							{
								IsValid = false,
								Offset = 0
							};

							continuationHistory.Add(contIndex, cont);
						}

						if (readDetails is ReadEventDetails)
						{
							resultsEvents.Clear();
							var statusCode = app.HandleHistoryEventReadRequest(config.Session, readDetails, nodeToRead, cont, resultsEvents);

							int availableSpace = availableSpacePerRequest;

							int numFit = 0;
							for (int j = 0; j < resultsEvents.Count; j++)
							{
								int sizeRequired = 4;
								for (int k = 0; k < resultsEvents[j].Length; k++)
								{
									sizeRequired += respBuf.VariantCodingSize(resultsEvents[j][k]);
								}

								if (availableSpace < sizeRequired)
								{
									break;
								}

								availableSpace -= sizeRequired;
								++numFit;
							}

							if (numFit < resultsEvents.Count)
							{
								cont.IsValid = true;
								cont.Offset += numFit;
							}
							else
							{
								cont.IsValid = false;

								availableContinuationPoints.Push(contIndex);
								continuationHistory.Remove(contIndex);
								cont = null;

								contIndex = -1;
							}

							if (cont == null)
							{
								contPoint = null;
							}
							else
							{
								contPoint = BitConverter.GetBytes(contIndex);
								if (statusCode == (uint)StatusCode.Good && cont.IsValid)
								{
									statusCode = (uint)StatusCode.GoodMoreData;
								}
							}

							succeeded &= respBuf.Encode(statusCode);
							succeeded &= respBuf.EncodeUAByteString(contPoint);

							succeeded &= respBuf.Encode(new NodeId(UAConst.HistoryEvent_Encoding_DefaultBinary));
							succeeded &= respBuf.Encode((byte)1);

							int eoSizePos = respBuf.Position;
							succeeded &= respBuf.Encode((UInt32)0);

							int posNumDataValue = respBuf.Position;
							succeeded &= respBuf.Encode((UInt32)0);

							int numDvs = 0;
							for (int j = 0; j < resultsEvents.Count; j++)
							{
								//succeeded &= respBuf.Encode(results[j]);
								succeeded &= respBuf.Encode((UInt32)resultsEvents[j].Length);
								for (int k = 0; k < resultsEvents[j].Length; k++)
								{
									succeeded &= respBuf.VariantEncode(resultsEvents[j][k]);
								}

								++numDvs;
							}

							succeeded &= respBuf.Encode((UInt32)numDvs, posNumDataValue);
							succeeded &= respBuf.Encode((UInt32)(respBuf.Position - eoSizePos - 4), eoSizePos);

							numNodesWritten++;
						}
						else
						{
							results.Clear();
							int? offsetContinueFit = null;
							var statusCode = app.HandleHistoryReadRequest(config.Session, readDetails, nodeToRead, cont, results, ref offsetContinueFit);

							int availableSpace = availableSpacePerRequest;

							int numFit = 0;
							for (int j = 0; j < results.Count; j++)
							{
								int sizeRequired = respBuf.CodingSize(results[j]);
								if (availableSpace < sizeRequired)
								{
									break;
								}

								availableSpace -= sizeRequired;
								++numFit;
							}

							if (numFit < results.Count || offsetContinueFit != null)
							{
								cont.IsValid = true;
								if (offsetContinueFit.HasValue && numFit > offsetContinueFit.Value)
								{
									cont.Offset += offsetContinueFit.Value;
								}
								else
								{
									cont.Offset += numFit;
								}
							}
							else
							{
								cont.IsValid = false;

								availableContinuationPoints.Push(contIndex);
								continuationHistory.Remove(contIndex);
								cont = null;

								contIndex = -1;
							}

							if (cont == null)
							{
								contPoint = null;
							}
							else
							{
								contPoint = BitConverter.GetBytes(contIndex);
								if (statusCode == (uint)StatusCode.Good && cont.IsValid)
								{
									statusCode = (uint)StatusCode.GoodMoreData;
								}
							}

							succeeded &= respBuf.Encode(statusCode);
							succeeded &= respBuf.EncodeUAByteString(contPoint);

							succeeded &= respBuf.Encode(new NodeId(UAConst.HistoryData_Encoding_DefaultBinary));
							succeeded &= respBuf.Encode((byte)1);

							int eoSizePos = respBuf.Position;
							succeeded &= respBuf.Encode((UInt32)0);

							int posNumDataValue = respBuf.Position;
							succeeded &= respBuf.Encode((UInt32)0);

							int numDvs = 0;
							for (int j = 0; j < results.Count; j++)
							{
								succeeded &= respBuf.Encode(results[j]);
								++numDvs;
							}

							succeeded &= respBuf.Encode((UInt32)numDvs, posNumDataValue);
							succeeded &= respBuf.Encode((UInt32)(respBuf.Position - eoSizePos - 4), eoSizePos);

							numNodesWritten++;
						}
					}

					succeeded &= respBuf.Encode((UInt32)numNodesWritten, numResultsPos);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_ReadRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				double maxAge;
				UInt32 timestampsToReturnUint;
				UInt32 noOfNodesToRead;
				TimestampsToReturn timestampsToReturn;

				if (!recvBuf.Decode(out maxAge)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out timestampsToReturnUint)) { return ErrorParseFail; }

				try
				{
					timestampsToReturn = (TimestampsToReturn)timestampsToReturnUint;
				}
				catch
				{
					return ErrorParseFail;
				}

				if (!recvBuf.Decode(out noOfNodesToRead)) { return ErrorParseFail; }

				var readValueIds = new ReadValueId[noOfNodesToRead];
				for (uint i = 0; i < noOfNodesToRead; i++)
				{
					if (!recvBuf.Decode(out readValueIds[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.ReadResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var respVals = app.HandleReadRequest(config.Session, readValueIds);
				if (respVals == null || respVals.Length != readValueIds.Length)
				{
					throw new Exception(string.Format("Read requested {0} ids, returned {1} response values", readValueIds.Length, respVals.Length));
				}

				succeeded &= respBuf.Encode((UInt32)respVals.Length);
				for (int i = 0; i < respVals.Length && succeeded; i++)
				{
					succeeded &= respBuf.Encode(respVals[i]);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_HistoryUpdateRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				// TODO: Verify

				Int32 NoOfHistoryUpdateDetails;

				if (!recvBuf.Decode(out NoOfHistoryUpdateDetails)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				var historyUpdates = new HistoryUpdateData[NoOfHistoryUpdateDetails];
				for (uint i = 0; i < NoOfHistoryUpdateDetails; i++)
				{
					NodeId typeId;
					byte body;
					UInt32 eoSize;

					if (!recvBuf.Decode(out typeId)) { return ErrorParseFail; }
					if (!typeId.EqualsNumeric(0, (uint)UAConst.UpdateDataDetails_Encoding_DefaultBinary))
					{
						DispatchMessage_WriteHeader(config, respBuf,
							(uint)RequestCode.HistoryUpdateResponse, reqHeader, (uint)StatusCode.BadHistoryOperationInvalid);
						DispatchMessage_SecureAndSend(config, respBuf);
						return (int)messageSize;
					}

					if (!recvBuf.Decode(out body)) { return ErrorParseFail; }
					if (body != 1)
					{
						DispatchMessage_WriteHeader(config, respBuf,
							(uint)RequestCode.HistoryUpdateResponse, reqHeader, (uint)StatusCode.BadHistoryOperationInvalid);
						DispatchMessage_SecureAndSend(config, respBuf);
						return (int)messageSize;
					}

					if (!recvBuf.Decode(out eoSize)) { return ErrorParseFail; }

					NodeId nodeId;
					UInt32 perform;
					UInt32 numValues;
					if (!recvBuf.Decode(out nodeId)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out perform)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out numValues)) { return ErrorParseFail; }

					var dv = new DataValue[numValues];
					for (uint j = 0; j < numValues; j++)
					{
						if (!recvBuf.Decode(out dv[i])) { return ErrorParseFail; }
					}

					try
					{
						historyUpdates[i] = new HistoryUpdateData(nodeId, (PerformUpdateType)perform, dv);
					}
					catch
					{
						DispatchMessage_WriteHeader(config, respBuf,
							(uint)RequestCode.HistoryUpdateResponse, reqHeader, (uint)StatusCode.BadHistoryOperationInvalid);
						DispatchMessage_SecureAndSend(config, respBuf);
						return (int)messageSize;
					}
				}

				var respVals = app.HandleHistoryUpdateRequest(config.Session, historyUpdates);

				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.HistoryUpdateResponse, reqHeader, (uint)StatusCode.Good);

				if (respVals == null || respVals.Length != historyUpdates.Length)
				{
					throw new Exception(string.Format("HistoryUpdate requested {0} ids, returned {1} response status codes", historyUpdates.Length, respVals.Length));
				}

				succeeded &= respBuf.Encode((UInt32)respVals.Length);
				for (int i = 0; i < respVals.Length && succeeded; i++)
				{
					succeeded &= respBuf.Encode(respVals[i]);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_WriteRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 NoOfNodesToWrite;

				if (!recvBuf.Decode(out NoOfNodesToWrite)) { return ErrorParseFail; }

				var writeValues = new WriteValue[NoOfNodesToWrite];
				for (uint i = 0; i < NoOfNodesToWrite; i++)
				{
					if (!recvBuf.Decode(out writeValues[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.WriteResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var respVals = app.HandleWriteRequest(config.Session, writeValues);
				if (respVals == null || respVals.Length != writeValues.Length)
				{
					throw new Exception(string.Format("Write requested {0} ids, returned {1} response status codes", writeValues.Length, respVals.Length));
				}

				succeeded &= respBuf.Encode((UInt32)respVals.Length);
				for (int i = 0; i < respVals.Length && succeeded; i++)
				{
					succeeded &= respBuf.Encode(respVals[i]);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_BrowseRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				NodeId viewId;
				Int64 viewTimestampsS;
				UInt32 viewVersion;
				UInt32 requestedMaxRefPerNode;

				if (!recvBuf.Decode(out viewId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out viewTimestampsS)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out viewVersion)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out requestedMaxRefPerNode)) { return ErrorParseFail; }

				requestedMaxRefPerNode = Math.Min(requestedMaxRefPerNode, MaxBrowseResults);
				if (requestedMaxRefPerNode == 0) { requestedMaxRefPerNode = MaxBrowseResults; }

				UInt32 noOfNodesToBrowse;
				if (!recvBuf.Decode(out noOfNodesToBrowse)) { return ErrorParseFail; }

				var browseDescs = new BrowseDescription[noOfNodesToBrowse];
				for (uint i = 0; i < noOfNodesToBrowse; i++)
				{
					if (!recvBuf.Decode(out browseDescs[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.BrowseResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				succeeded &= respBuf.Encode((UInt32)noOfNodesToBrowse);
				var references = new List<ReferenceDescription>();
				for (uint i = 0; i < noOfNodesToBrowse && succeeded; i++)
				{
					references.Clear();
					StatusCode status = StatusCode.Good;
					byte[] contPoint = null;

					if (availableContinuationPoints.Count > 0)
					{
						int contIndex = availableContinuationPoints.Pop();
						var cont = new ContinuationPointBrowse(browseDescs[i], (int)requestedMaxRefPerNode);

						status = app.HandleBrowseRequest(config.Session, browseDescs[i], references, (int)requestedMaxRefPerNode, cont);

						if (cont.IsValid)
						{
							contPoint = BitConverter.GetBytes(contIndex);
							continuationBrowse.Add(contIndex, cont);
						}
						else
						{
							availableContinuationPoints.Push(contIndex);
						}
					}
					else
					{
						status = StatusCode.BadNoContinuationPoints;
					}

					succeeded &= respBuf.Encode((UInt32)status);
					succeeded &= respBuf.EncodeUAByteString(contPoint);
					succeeded &= respBuf.Encode((UInt32)references.Count);
					for (int j = 0; j < references.Count; j++)
					{
						succeeded &= respBuf.Encode(references[j]);
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_BrowseNextRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				bool ReleaseContinuationPoints;
				UInt32 NoOfContinuationPoints;

				if (!recvBuf.Decode(out ReleaseContinuationPoints)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out NoOfContinuationPoints)) { return ErrorParseFail; }

				var browseContPoints = new byte[NoOfContinuationPoints][];
				for (uint i = 0; i < NoOfContinuationPoints; i++)
				{
					if (!recvBuf.DecodeUAByteString(out browseContPoints[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.BrowseNextResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				if (ReleaseContinuationPoints)
				{
					succeeded &= respBuf.Encode((UInt32)0);

					for (uint i = 0; i < NoOfContinuationPoints; i++)
					{
						byte[] contPoint = browseContPoints[i];
						ContinuationPointBrowse cont = null;

						int contIndex = -1;
						try
						{
							contIndex = BitConverter.ToInt32(contPoint, 0);
						}
						catch
						{
							contIndex = -1;
						}

						if (continuationBrowse.TryGetValue(contIndex, out cont))
						{
							cont.IsValid = false;

							availableContinuationPoints.Push(contIndex);
							continuationBrowse.Remove(contIndex);
							contPoint = null;
						}
					}
				}
				else
				{
					succeeded &= respBuf.Encode((UInt32)NoOfContinuationPoints);
					var references = new List<ReferenceDescription>();
					for (uint i = 0; i < NoOfContinuationPoints && succeeded; i++)
					{
						ContinuationPointBrowse cont = null;
						references.Clear();
						StatusCode status = StatusCode.Good;
						byte[] contPoint = browseContPoints[i];

						int contIndex = -1;
						try
						{
							contIndex = BitConverter.ToInt32(contPoint, 0);
						}
						catch
						{
							contIndex = -1;
						}

						if (continuationBrowse.TryGetValue(contIndex, out cont))
						{
							status = app.HandleBrowseRequest(config.Session, cont.Desc, references, cont.MaxReferencesPerNode, cont);

							if (cont.IsValid)
							{
								contPoint = BitConverter.GetBytes(contIndex);
								continuationBrowse[contIndex] = cont;
							}
							else
							{
								availableContinuationPoints.Push(contIndex);
								continuationBrowse.Remove(contIndex);
								contPoint = null;
							}
						}
						else
						{
							contPoint = null;
							status = StatusCode.BadContinuationPointInvalid;
						}

						succeeded &= respBuf.Encode((UInt32)status);
						succeeded &= respBuf.EncodeUAByteString(contPoint);
						succeeded &= respBuf.Encode((UInt32)references.Count);
						for (int j = 0; j < references.Count; j++)
						{
							succeeded &= respBuf.Encode(references[j]);
						}
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_TranslateBrowsePathsToNodeIdsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				// TODO: Verify

				UInt32 NoOfBrowsePaths;
				BrowsePath[] BrowsePaths;

				if (!recvBuf.Decode(out NoOfBrowsePaths)) { return ErrorParseFail; }
				BrowsePaths = new BrowsePath[NoOfBrowsePaths];
				for (uint i = 0; i < NoOfBrowsePaths; i++)
				{
					if (!recvBuf.Decode(out BrowsePaths[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.TranslateBrowsePathsToNodeIdsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				var targets = new List<BrowsePathTarget>();
				succeeded &= respBuf.Encode((UInt32)NoOfBrowsePaths);
				for (uint i = 0; i < NoOfBrowsePaths; i++)
				{
					targets.Clear();
					var status = app.HandleTranslateBrowsePathRequest(config.Session, BrowsePaths[i], targets);
					BrowsePathResult res = new BrowsePathResult(status, targets.Count > 0 ? targets.ToArray() : null);
					succeeded &= respBuf.Encode(res);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_CallRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				// TODO: Verify

				UInt32 NoofMethodsToCall;

				if (!recvBuf.Decode(out NoofMethodsToCall)) { return ErrorParseFail; }
				var reqs = new CallMethodRequest[NoofMethodsToCall];
				for (uint i = 0; i < NoofMethodsToCall; i++)
				{
					NodeId objectId, nodeId;
					if (!recvBuf.Decode(out objectId)) { return ErrorParseFail; }
					if (!recvBuf.Decode(out nodeId)) { return ErrorParseFail; }

					UInt32 numVariants;
					if (!recvBuf.Decode(out numVariants)) { return ErrorParseFail; }
					var inputArgs = new object[numVariants];
					for (uint j = 0; j < numVariants; j++)
					{
						if (!recvBuf.VariantDecode(out inputArgs[j])) { return ErrorParseFail; }
					}
					reqs[i] = new CallMethodRequest(objectId, nodeId, inputArgs);
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.CallResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				succeeded &= respBuf.Encode((UInt32)NoofMethodsToCall);
				for (uint i = 0; i < NoofMethodsToCall; i++)
				{
					succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
					// InputArgumentResults: Array of StatusCode
					succeeded &= respBuf.Encode((UInt32)0);
					// InputArgumentDiagnosticInfos
					succeeded &= respBuf.Encode((UInt32)0);
					// OutputArguments: Array of Variant
					succeeded &= respBuf.Encode((UInt32)0);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_RegisterNodesRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.RegisterNodesResponse, reqHeader, (uint)StatusCode.BadNotSupported);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// NoOfRegisteredNodeIds
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_CreateSubscriptionRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				double RequestedPublishingInterval;
				UInt32 RequestedLifetimeCount, RequestedMaxKeepAliveCount, MaxNotificationsPerPublish;
				bool PublishingEnabled;
				byte Priority;

				if (!recvBuf.Decode(out RequestedPublishingInterval)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out RequestedLifetimeCount)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out RequestedMaxKeepAliveCount)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out MaxNotificationsPerPublish)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out PublishingEnabled)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out Priority)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.CreateSubscriptionResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				UInt32 subId = nextSubscriptionID++;
				if (subscriptionMap.ContainsKey(subId))
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Could not allocate subscription ID {1}", LoggerID(), subId));
					}

					UAStatusCode = (uint)StatusCode.BadSubscriptionIdInvalid;
					return ErrorInternal;
				}

				double revisedPublishInterval = RequestedPublishingInterval;
				UInt32 revisedLifetimeCount = RequestedLifetimeCount;
				UInt32 revisedMaxKeepAliveCount = RequestedMaxKeepAliveCount;
				succeeded &= respBuf.Encode(subId);
				succeeded &= respBuf.Encode(revisedPublishInterval);
				succeeded &= respBuf.Encode(revisedLifetimeCount);
				succeeded &= respBuf.Encode(revisedMaxKeepAliveCount);

				revisedPublishInterval = Math.Max(0, revisedPublishInterval);

				subscriptionMap.Add(subId, new Subscription()
				{
					SubscriptionId = subId,

					PublishingInterval = revisedPublishInterval,
					LifetimeCount = revisedLifetimeCount,
					MaxKeepAliveCount = revisedMaxKeepAliveCount,
					MaxNotificationsPerPublish = Math.Max(1, MaxNotificationsPerPublish),
					PublishingEnabled = PublishingEnabled,
					Priority = Priority,

					PublishInterval = TimeSpan.FromMilliseconds(revisedPublishInterval / 2),
					PublishKeepAliveInterval = TimeSpan.FromMilliseconds(Math.Max(1, (revisedPublishInterval / 2) * RequestedMaxKeepAliveCount)),

					ChangeNotification = Subscription.ChangeNotificationType.None
				});

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_SetPublishingModeRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				bool PublishingEnabled;
				UInt32 NoOfSubscriptionIds;
				UInt32[] SubscriptionIds;

				if (!recvBuf.Decode(out PublishingEnabled)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out NoOfSubscriptionIds)) { return ErrorParseFail; }

				SubscriptionIds = new UInt32[NoOfSubscriptionIds];
				for (int i = 0; i < NoOfSubscriptionIds; i++)
				{
					if (!recvBuf.Decode(out SubscriptionIds[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.SetPublishingModeResponse, reqHeader, (uint)StatusCode.Good);

				succeeded &= respBuf.Encode((UInt32)NoOfSubscriptionIds);
				for (int i = 0; i < NoOfSubscriptionIds; i++)
				{
					Subscription sub = null;
					if (subscriptionMap.TryGetValue(SubscriptionIds[i], out sub))
					{
						sub.PublishingEnabled = PublishingEnabled;
						succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
					}
					else
					{
						succeeded &= respBuf.Encode((UInt32)StatusCode.BadSubscriptionIdInvalid);
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_ModifySubscriptionRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 SubscriptionId;
				UInt32 RequestedLifetimeCount, RequestedMaxKeepAliveCount, MaxNotificationsPerPublish;
				double RequestedPublishingInterval;
				byte Priority;

				if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out RequestedPublishingInterval)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out RequestedLifetimeCount)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out RequestedMaxKeepAliveCount)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out MaxNotificationsPerPublish)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out Priority)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = true;

				Subscription sub = null;
				if (subscriptionMap.TryGetValue(SubscriptionId, out sub))
				{
					succeeded = DispatchMessage_WriteHeader(config, respBuf,
						(uint)RequestCode.ModifySubscriptionResponse, reqHeader, (uint)StatusCode.Good);

					sub.PublishingInterval = Math.Max(0, RequestedPublishingInterval);
					sub.LifetimeCount = RequestedLifetimeCount;
					sub.MaxKeepAliveCount = RequestedMaxKeepAliveCount;
					sub.MaxNotificationsPerPublish = Math.Max(1, MaxNotificationsPerPublish);
					sub.Priority = Priority;

					sub.PublishInterval = TimeSpan.FromMilliseconds(sub.PublishingInterval / 2);
					sub.PublishKeepAliveInterval = TimeSpan.FromMilliseconds(Math.Max(1, (sub.PublishingInterval / 2) * RequestedMaxKeepAliveCount));

					succeeded &= respBuf.Encode((double)sub.PublishingInterval);
					succeeded &= respBuf.Encode((UInt32)sub.LifetimeCount);
					succeeded &= respBuf.Encode((UInt32)sub.MaxKeepAliveCount);
				}
				else
				{
					succeeded = DispatchMessage_WriteHeader(config, respBuf,
						(uint)RequestCode.ModifySubscriptionResponse, reqHeader, (uint)StatusCode.BadSubscriptionIdInvalid);

					succeeded &= respBuf.Encode((double)0);
					succeeded &= respBuf.Encode((UInt32)0);
					succeeded &= respBuf.Encode((UInt32)0);
				}

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_DeleteSubscriptionsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 NoOfSubIds;
				UInt32[] SubIds;

				if (!recvBuf.Decode(out NoOfSubIds)) { return ErrorParseFail; }
				SubIds = new UInt32[NoOfSubIds];
				for (uint i = 0; i < NoOfSubIds; i++)
				{
					if (!recvBuf.Decode(out SubIds[i])) { return ErrorParseFail; }
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.DeleteSubscriptionsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				succeeded &= respBuf.Encode(NoOfSubIds);
				for (uint i = 0; i < NoOfSubIds; i++)
				{
					Subscription sub = null;
					if (!subscriptionMap.TryGetValue(SubIds[i], out sub))
					{
						succeeded &= respBuf.Encode((UInt32)StatusCode.BadSubscriptionIdInvalid);
					}
					else
					{
						foreach (var mi in sub.MonitoredItems.Values)
						{
							app.MonitorRemove(config.Session, mi);
						}

						succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
						subscriptionMap.Remove(SubIds[i]);
					}
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_TransferSubscriptionsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.TransferSubscriptionsResponse, reqHeader, (uint)StatusCode.BadNotSupported);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Results
				succeeded &= respBuf.Encode((UInt32)0);
				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_CreateMonitoredItemsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 SubscriptionId, TimestampsToReturnUint, NoOfItemsToCreate;
				TimestampsToReturn timestampsToReturn;

				if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out TimestampsToReturnUint)) { return ErrorParseFail; }

				try
				{
					timestampsToReturn = (TimestampsToReturn)TimestampsToReturnUint;
				}
				catch
				{
					return ErrorParseFail;
				}

				if (!recvBuf.Decode(out NoOfItemsToCreate)) { return ErrorParseFail; }
				var createRequests = new MonitoredItemCreateRequest[NoOfItemsToCreate];
				var createResponses = new MonitoredItemCreateResult[NoOfItemsToCreate];

				Subscription sub = null;
				if (!subscriptionMap.TryGetValue(SubscriptionId, out sub))
				{
					sub = null;
				}

				for (uint i = 0; i < NoOfItemsToCreate; i++)
				{
					if (!recvBuf.Decode(out createRequests[i])) { return ErrorParseFail; }

					if (sub == null)
					{
						createResponses[i] = new MonitoredItemCreateResult(StatusCode.BadSubscriptionIdInvalid, createRequests[i].RequestedParameters.ClientHandle, 0, 0, null);
						continue;
					}

					if (sub.MonitoredItems.Count >= MaxMonitoredPerSubscription)
					{
						createResponses[i] = new MonitoredItemCreateResult(StatusCode.BadTooManyMonitoredItems, createRequests[i].RequestedParameters.ClientHandle, 0, 0, null);
						continue;
					}

					if (createRequests[i].ItemToMonitor.AttributeId != NodeAttribute.Value &&
						createRequests[i].ItemToMonitor.AttributeId != NodeAttribute.EventNotifier)
					{
						createResponses[i] = new MonitoredItemCreateResult(StatusCode.BadNodeAttributesInvalid, createRequests[i].RequestedParameters.ClientHandle, 0, 0, null);
						continue;
					}

					MonitoredItem mi = null;
					var miHandle = createRequests[i].RequestedParameters.ClientHandle;

					if (sub.MonitoredItems.ContainsKey(miHandle))
					{
						mi = sub.MonitoredItems[miHandle];
						app.MonitorRemove(config.Session, mi);
						sub.MonitoredItems.Remove(miHandle);
						continue;
					}

					SimpleAttributeOperand[] filterSelectClauses = null;
					if (createRequests[i].RequestedParameters.Filter != null)
					{
						filterSelectClauses = createRequests[i].RequestedParameters.Filter.SelectClauses;

						//Console.WriteLine("Filter select clause {0}", filterSelectClauses.Length);
						//foreach (var sc in filterSelectClauses)
						//{
						//	Console.WriteLine("Filter select clause \"{0}\"", string.Join(", ", sc.BrowsePath.Select(p => p.Name)));
						//}
					}

					mi = new MonitoredItem(sub, filterSelectClauses)
					{
						MonitoredItemId = miHandle,

						ItemToMonitor = createRequests[i].ItemToMonitor,
						Mode = createRequests[i].Mode,
						Parameters = createRequests[i].RequestedParameters,

						QueueSize = Math.Max(1, Math.Min(MonitoredItem.MaxQueueSize, (int)createRequests[i].RequestedParameters.QueueSize))
					};

					if (!app.MonitorAdd(config.Session, mi))
					{
						createResponses[i] = new MonitoredItemCreateResult(StatusCode.BadNodeIdUnknown, createRequests[i].RequestedParameters.ClientHandle, 0, 0, null);
						continue;
					}

					sub.MonitoredItems.Add(mi.MonitoredItemId, mi);
					sub.ChangeNotification = Subscription.ChangeNotificationType.Immediate;

					double samplingInterval = createRequests[i].RequestedParameters.SamplingInterval;
					if (samplingInterval < 1)
					{
						samplingInterval = 1000;
					}

					createResponses[i] = new MonitoredItemCreateResult(StatusCode.Good, createRequests[i].RequestedParameters.ClientHandle, samplingInterval, (uint)mi.QueueSize, null);
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.CreateMonitoredItemsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Results
				succeeded &= respBuf.Encode((UInt32)createResponses.Length);
				for (int i = 0; i < createResponses.Length; i++)
				{
					succeeded &= respBuf.Encode(createResponses[i]);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_SetMonitoringModeRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 SubscriptionId, MonitoringMode, NoOfItemsToModify;

				if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out MonitoringMode)) { return ErrorParseFail; }

				if (!recvBuf.Decode(out NoOfItemsToModify)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.SetMonitoringModeResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Results
				succeeded &= respBuf.Encode((UInt32)NoOfItemsToModify);
				for (int i = 0; i < NoOfItemsToModify; i++)
				{
					succeeded &= respBuf.Encode((UInt32)0);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_ModifyMonitoredItemsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 SubscriptionId, TimestampsToReturnUint, NoOfItemsToModify;
				TimestampsToReturn timestampsToReturn;

				if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out TimestampsToReturnUint)) { return ErrorParseFail; }

				try
				{
					timestampsToReturn = (TimestampsToReturn)TimestampsToReturnUint;
				}
				catch
				{
					return ErrorParseFail;
				}

				if (!recvBuf.Decode(out NoOfItemsToModify)) { return ErrorParseFail; }

				Subscription sub = null;
				if (!subscriptionMap.TryGetValue(SubscriptionId, out sub))
				{
					sub = null;
				}

				var modifyRequests = new MonitoredItemModifyRequest[NoOfItemsToModify];
				var modifyResults = new MonitoredItemModifyResult[NoOfItemsToModify];
				for (uint i = 0; i < NoOfItemsToModify; i++)
				{
					if (!recvBuf.Decode(out modifyRequests[i])) { return ErrorParseFail; }
				}

				for (uint i = 0; i < NoOfItemsToModify; i++)
				{
					if (sub == null)
					{
						modifyResults[i] = new MonitoredItemModifyResult(StatusCode.BadSubscriptionIdInvalid, 0, 0, null);
						continue;
					}

					MonitoredItem mi = null;
					if (!sub.MonitoredItems.TryGetValue(modifyRequests[i].MonitoredItemId, out mi))
					{
						modifyResults[i] = new MonitoredItemModifyResult(StatusCode.BadMonitoredItemIdInvalid, 0, 0, null);
						continue;
					}

					mi.QueueSize = Math.Max(1, Math.Min(MonitoredItem.MaxQueueSize, (int)modifyRequests[i].Parameters.QueueSize));
					mi.Parameters = modifyRequests[i].Parameters;
					mi.FilterSelectClauses = modifyRequests[i].Parameters.Filter.SelectClauses;
					modifyResults[i] = new MonitoredItemModifyResult(StatusCode.Good, -1, (uint)mi.QueueSize, null);
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.ModifyMonitoredItemsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Results
				succeeded &= respBuf.Encode((UInt32)modifyResults.Length);
				for (int i = 0; i < modifyResults.Length; i++)
				{
					succeeded &= respBuf.Encode(modifyResults[i]);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_DeleteMonitoredItemsRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				UInt32 SubscriptionId, NoOfMonitoredItemIds;
				UInt32[] MonitoredItemIds;

				if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				if (!recvBuf.Decode(out NoOfMonitoredItemIds)) { return ErrorParseFail; }

				MonitoredItemIds = new UInt32[NoOfMonitoredItemIds];
				for (uint i = 0; i < NoOfMonitoredItemIds; i++)
				{
					if (!recvBuf.Decode(out MonitoredItemIds[i])) { return ErrorParseFail; }
				}

				Subscription sub = null;
				if (!subscriptionMap.TryGetValue(SubscriptionId, out sub))
				{
					sub = null;
				}

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.DeleteMonitoredItemsResponse, reqHeader, (uint)StatusCode.Good);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Results
				succeeded &= respBuf.Encode(NoOfMonitoredItemIds);
				for (uint i = 0; i < NoOfMonitoredItemIds; i++)
				{
					if (sub == null)
					{
						succeeded &= respBuf.Encode((UInt32)StatusCode.BadSubscriptionIdInvalid);
						continue;
					}

					MonitoredItem mi = null;
					if (!sub.MonitoredItems.TryGetValue(MonitoredItemIds[i], out mi))
					{
						succeeded &= respBuf.Encode((UInt32)StatusCode.BadMonitoredItemIdInvalid);
						continue;
					}

					app.MonitorRemove(config.Session, mi);
					sub.MonitoredItems.Remove(MonitoredItemIds[i]);

					succeeded &= respBuf.Encode((UInt32)StatusCode.Good);
				}

				// DiagnosticInfos
				succeeded &= respBuf.Encode((UInt32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_RepublishRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				//UInt32 SubscriptionId, TimestampsToReturnUint, NoOfItemsToCreate;
				//TimestampsToReturn timestampsToReturn;

				//if (!recvBuf.Decode(out SubscriptionId)) { return ErrorParseFail; }
				//if (!recvBuf.Decode(out TimestampsToReturnUint)) { return ErrorParseFail; }

				var respBuf = new MemoryBuffer(maximumMessageSize);
				bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
					(uint)RequestCode.RepublishResponse, reqHeader, (uint)StatusCode.BadNotSupported);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				// Sequence
				succeeded &= respBuf.Encode((UInt32)0);

				// PublishTime
				succeeded &= respBuf.Encode((Int64)0);

				// NoOfNotificationData
				succeeded &= respBuf.Encode((Int32)0);

				if (!succeeded)
				{
					return ErrorRespWrite;
				}

				DispatchMessage_SecureAndSend(config, respBuf);
				return (int)messageSize;
			}

			protected int DispatchMessage_PublishRequest(SLChannel config, RequestHeader reqHeader, MemoryBuffer recvBuf, uint messageSize)
			{
				if (pendingNotificationRequests.Count < MaxPublishRequests)
				{
					UInt32 NoOfSubscriptionAcknowledgements;

					if (!recvBuf.Decode(out NoOfSubscriptionAcknowledgements)) { return ErrorParseFail; }
					if (NoOfSubscriptionAcknowledgements == 0xFFFFFFFFu)
					{
						NoOfSubscriptionAcknowledgements = 0;
					}

					for (uint i = 0; i < NoOfSubscriptionAcknowledgements; i++)
					{
						UInt32 subId, seqNum;
						if (!recvBuf.Decode(out subId)) { return ErrorParseFail; }
						if (!recvBuf.Decode(out seqNum)) { return ErrorParseFail; }

						Queue<uint> seqQueue = null;
						if (pendingSubscriptionAcknowledgements.TryGetValue(subId, out seqQueue))
						{
							seqQueue.Enqueue(seqNum);
						}
						else
						{
							pendingSubscriptionAcknowledgements.Add(subId, new Queue<uint>(new uint[] { seqNum }));
						}
					}

					pendingNotificationRequests.Enqueue(reqHeader);
				}
				else
				{
					if (logger != null)
					{
						logger.Log(LogLevel.Error, string.Format("{0}: Too many publish requests (max is {1}), sent BadTooManyPublishRequests", LoggerID(), 1));
					}

					var respBuf = new MemoryBuffer(maximumMessageSize);
					bool succeeded = DispatchMessage_WriteHeader(config, respBuf,
						(uint)RequestCode.PublishRequest, reqHeader, (uint)StatusCode.BadTooManyPublishRequests);

					if (!succeeded)
					{
						return ErrorRespWrite;
					}

					DispatchMessage_SecureAndSend(config, respBuf);
				}

				return (int)messageSize;
			}
		}
	}
}
