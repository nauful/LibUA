using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace LibUA
{
	namespace Core
	{
		public static class Types
		{
			public static bool StatusCodeIsGood(uint code) { return (code & 0xC0000000) == 0; }
			public static bool StatusCodeIsUncertain(uint code) { return (code & 0x40000000) != 0; }
			public static bool StatusCodeIsBad(uint code) { return (code & 0x80000000) != 0; }

			public static string[] SLSecurityPolicyUris =
			{
				"invalid",
				"http://opcfoundation.org/UA/SecurityPolicy#None",
				"http://opcfoundation.org/UA/SecurityPolicy#Basic256",
				"http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
				"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
			};

			public const string TransportProfileBinary = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
			public const string SignatureAlgorithmSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
			public const string SignatureAlgorithmSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
			public const string SignatureAlgorithmRsa15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

			public const string IdentityTokenAnonymous = "anonymous";
		}

		public enum MessageType : uint
		{
			Hello = 0x4C4548,
			Acknowledge = 0x4B4341,
			Error = 0x525245,
			Open = 0x4E504F,
			Message = 0x47534D,
			Close = 0x4F4C43,
		}

		public enum UserIdentityTokenType : uint
		{
			Anonymous = 321,
			UserNameIdentityToken = 324,
		}

		public class UserIdentityAnonymousToken
		{
			public string PolicyId { get; protected set; }
			public UserIdentityAnonymousToken(string PolicyId)
			{
				this.PolicyId = PolicyId;
			}
		}

		public class UserIdentityUsernameToken
		{
			public string PolicyId { get; protected set; }
			public string Username { get; protected set; }
			public byte[] PasswordHash { get; protected set; }
			public string Algorithm { get; protected set; }

			public UserIdentityUsernameToken(string PolicyId, string Username, byte[] PasswordHash, string Algorithm)
			{
				this.PolicyId = PolicyId;
				this.Username = Username;
				this.PasswordHash = PasswordHash;
				this.Algorithm = Algorithm;
			}
		}

		public enum StatusCode : uint
		{
			Good = 0,

			BadGeneric = 0x80000000,
			UncertainGeneric = 0x40000000,

			BadUnexpectedError = 0x80010000, // An unexpected error occurred.
			BadInternalError = 0x80020000, // An internal error occurred as a result of a programming or configuration error.
			BadOutOfMemory = 0x80030000, // Not enough memory to complete the operation.
			BadResourceUnavailable = 0x80040000, // An operating system resource is not available.
			BadCommunicationError = 0x80050000, // A low level communication error occurred.
			BadEncodingError = 0x80060000, // Encoding halted because of invalid data in the objects being serialized.
			BadDecodingError = 0x80070000, // Decoding halted because of invalid data in the stream.
			BadEncodingLimitsExceeded = 0x80080000, // The message encoding/decoding limits imposed by the stack have been exceeded.
			BadRequestTooLarge = 0x80B80000, // The request message size exceeds limits set by the server.
			BadResponseTooLarge = 0x80B90000, // The response message size exceeds limits set by the client.
			BadUnknownResponse = 0x80090000, // An unrecognized response was received from the server.
			BadTimeout = 0x800A0000, // The operation timed out.
			BadServiceUnsupported = 0x800B0000, // The server does not support the requested service.
			BadShutdown = 0x800C0000, // The operation was cancelled because the application is shutting down.
			BadServerNotConnected = 0x800D0000, // The operation could not complete because the client is not connected to the server.
			BadServerHalted = 0x800E0000, // The server has stopped and cannot process any requests.
			BadNothingToDo = 0x800F0000, // There was nothing to do because the client passed a list of operations with no elements.
			BadTooManyOperations = 0x80100000, // The request could not be processed because it specified too many operations.
			BadTooManyMonitoredItems = 0x80DB0000, // The request could not be processed because there are too many monitored items in the subscription.
			BadDataTypeIdUnknown = 0x80110000, // The extension object cannot be (de)serialized because the data type id is not recognized.
			BadCertificateInvalid = 0x80120000, // The certificate provided as a parameter is not valid.
			BadSecurityChecksFailed = 0x80130000, // An error occurred verifying security.
			BadCertificateTimeInvalid = 0x80140000, // The Certificate has expired or is not yet valid.
			BadCertificateIssuerTimeInvalid = 0x80150000, // An Issuer Certificate has expired or is not yet valid.
			BadCertificateHostNameInvalid = 0x80160000, // The HostName used to connect to a Server does not match a HostName in the Certificate.
			BadCertificateUriInvalid = 0x80170000, // The URI specified in the ApplicationDescription does not match the URI in the Certificate.
			BadCertificateUseNotAllowed = 0x80180000, // The Certificate may not be used for the requested operation.
			BadCertificateIssuerUseNotAllowed = 0x80190000, // The Issuer Certificate may not be used for the requested operation.
			BadCertificateUntrusted = 0x801A0000, // The Certificate is not trusted.
			BadCertificateRevocationUnknown = 0x801B0000, // It was not possible to determine if the Certificate has been revoked.
			BadCertificateIssuerRevocationUnknown = 0x801C0000, // It was not possible to determine if the Issuer Certificate has been revoked.
			BadCertificateRevoked = 0x801D0000, // The Certificate has been revoked.
			BadCertificateIssuerRevoked = 0x801E0000, // The Issuer Certificate has been revoked.
			BadUserAccessDenied = 0x801F0000, // User does not have permission to perform the requested operation.
			BadIdentityTokenInvalid = 0x80200000, // The user identity token is not valid.
			BadIdentityTokenRejected = 0x80210000, // The user identity token is valid but the server has rejected it.
			BadSecureChannelIdInvalid = 0x80220000, // The specified secure channel is no longer valid.
			BadInvalidTimestamp = 0x80230000, // The timestamp is outside the range allowed by the server.
			BadNonceInvalid = 0x80240000, // The nonce does appear to be not a random value or it is not the correct length.
			BadSessionIdInvalid = 0x80250000, // The session id is not valid.
			BadSessionClosed = 0x80260000, // The session was closed by the client.
			BadSessionNotActivated = 0x80270000, // The session cannot be used because ActivateSession has not been called.
			BadSubscriptionIdInvalid = 0x80280000, // The subscription id is not valid.
			BadRequestHeaderInvalid = 0x802A0000, // The header for the request is missing or invalid.
			BadTimestampsToReturnInvalid = 0x802B0000, // The timestamps to return parameter is invalid.
			BadRequestCancelledByClient = 0x802C0000, // The request was cancelled by the client.
			GoodSubscriptionTransferred = 0x002D0000, // The subscription was transferred to another session.
			GoodCompletesAsynchronously = 0x002E0000, // The processing will complete asynchronously.
			GoodOverload = 0x002F0000, // Sampling has slowed down due to resource limitations.
			GoodClamped = 0x00300000, // The value written was accepted but was clamped.
			BadNoCommunication = 0x80310000, // Communication with the data source is defined
			BadWaitingForInitialData = 0x80320000, // Waiting for the server to obtain values from the underlying data source.
			BadNodeIdInvalid = 0x80330000, // The syntax of the node id is not valid.
			BadNodeIdUnknown = 0x80340000, // The node id refers to a node that does not exist in the server address space.
			BadAttributeIdInvalid = 0x80350000, // The attribute is not supported for the specified Node.
			BadIndexRangeInvalid = 0x80360000, // The syntax of the index range parameter is invalid.
			BadIndexRangeNoData = 0x80370000, // No data exists within the range of indexes specified.
			BadDataEncodingInvalid = 0x80380000, // The data encoding is invalid.
			BadDataEncodingUnsupported = 0x80390000, // The server does not support the requested data encoding for the node.
			BadNotReadable = 0x803A0000, // The access level does not allow reading or subscribing to the Node.
			BadNotWritable = 0x803B0000, // The access level does not allow writing to the Node.
			BadOutOfRange = 0x803C0000, // The value was out of range.
			BadNotSupported = 0x803D0000, // The requested operation is not supported.
			BadNotFound = 0x803E0000, // A requested item was not found or a search operation ended without success.
			BadObjectDeleted = 0x803F0000, // The object cannot be used because it has been deleted.
			BadNotImplemented = 0x80400000, // Requested operation is not implemented.
			BadMonitoringModeInvalid = 0x80410000, // The monitoring mode is invalid.
			BadMonitoredItemIdInvalid = 0x80420000, // The monitoring item id does not refer to a valid monitored item.
			BadMonitoredItemFilterInvalid = 0x80430000, // The monitored item filter parameter is not valid.
			BadMonitoredItemFilterUnsupported = 0x80440000, // The server does not support the requested monitored item filter.
			BadFilterNotAllowed = 0x80450000, // A monitoring filter cannot be used in combination with the attribute specified.
			BadStructureMissing = 0x80460000, // A mandatory structured parameter was missing or null.
			BadEventFilterInvalid = 0x80470000, // The event filter is not valid.
			BadContentFilterInvalid = 0x80480000, // The content filter is not valid.
			BadFilterOperatorInvalid = 0x80C10000, // An unregognized operator was provided in a filter.
			BadFilterOperatorUnsupported = 0x80C20000, // A valid operator was provided
			BadFilterOperandCountMismatch = 0x80C30000, // The number of operands provided for the filter operator was less then expected for the operand provided.
			BadFilterOperandInvalid = 0x80490000, // The operand used in a content filter is not valid.
			BadFilterElementInvalid = 0x80C40000, // The referenced element is not a valid element in the content filter.
			BadFilterLiteralInvalid = 0x80C50000, // The referenced literal is not a valid value.
			BadContinuationPointInvalid = 0x804A0000, // The continuation point provide is longer valid.
			BadNoContinuationPoints = 0x804B0000, // The operation could not be processed because all continuation points have been allocated.
			BadReferenceTypeIdInvalid = 0x804C0000, // The operation could not be processed because all continuation points have been allocated.
			BadBrowseDirectionInvalid = 0x804D0000, // The browse direction is not valid.
			BadNodeNotInView = 0x804E0000, // The node is not part of the view.
			BadServerUriInvalid = 0x804F0000, // The ServerUri is not a valid URI.
			BadServerNameMissing = 0x80500000, // No ServerName was specified.
			BadDiscoveryUrlMissing = 0x80510000, // No DiscoveryUrl was specified.
			BadSempahoreFileMissing = 0x80520000, // The semaphore file specified by the client is not valid.
			BadRequestTypeInvalid = 0x80530000, // The security token request type is not valid.
			BadSecurityModeRejected = 0x80540000, // The security mode does not meet the requirements set by the Server.
			BadSecurityPolicyRejected = 0x80550000, // The security policy does not meet the requirements set by the Server.
			BadTooManySessions = 0x80560000, // The server has reached its maximum number of sessions.
			BadUserSignatureInvalid = 0x80570000, // The user token signature is missing or invalid.
			BadApplicationSignatureInvalid = 0x80580000, // The signature generated with the client certificate is missing or invalid.
			BadNoValidCertificates = 0x80590000, // The client did not provide at least one software certificate that is valid and meets the profile requirements for the server.
			BadIdentityChangeNotSupported = 0x80C60000, // The Server does not support changing the user identity assigned to the session.
			BadRequestCancelledByRequest = 0x805A0000, // The request was cancelled by the client with the Cancel service.
			BadParentNodeIdInvalid = 0x805B0000, // The parent node id does not to refer to a valid node.
			BadReferenceNotAllowed = 0x805C0000, // The reference could not be created because it violates constraints imposed by the data model.
			BadNodeIdRejected = 0x805D0000, // The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client.
			BadNodeIdExists = 0x805E0000, // The requested node id is already used by another node.
			BadNodeClassInvalid = 0x805F0000, // The node class is not valid.
			BadBrowseNameInvalid = 0x80600000, // The browse name is invalid.
			BadBrowseNameDuplicated = 0x80610000, // The browse name is not unique among nodes that share the same relationship with the parent.
			BadNodeAttributesInvalid = 0x80620000, // The node attributes are not valid for the node class.
			BadTypeDefinitionInvalid = 0x80630000, // The type definition node id does not reference an appropriate type node.
			BadSourceNodeIdInvalid = 0x80640000, // The source node id does not reference a valid node.
			BadTargetNodeIdInvalid = 0x80650000, // The target node id does not reference a valid node.
			BadDuplicateReferenceNotAllowed = 0x80660000, // The reference type between the nodes is already defined.
			BadInvalidSelfReference = 0x80670000, // The server does not allow this type of self reference on this node.
			BadReferenceLocalOnly = 0x80680000, // The reference type is not valid for a reference to a remote server.
			BadNoDeleteRights = 0x80690000, // The server will not allow the node to be deleted.
			UncertainReferenceNotDeleted = 0x40BC0000, // The server was not able to delete all target references.
			BadServerIndexInvalid = 0x806A0000, // The server index is not valid.
			BadViewIdUnknown = 0x806B0000, // The view id does not refer to a valid view node.
			BadViewTimestampInvalid = 0x80C90000, // The view timestamp is not available or not supported.
			BadViewParameterMismatch = 0x80CA0000, // The view parameters are not consistent with each other.
			BadViewVersionInvalid = 0x80CB0000, // The view version is not available or not supported.
			UncertainNotAllNodesAvailable = 0x40C00000, // The list of references may not be complete because the underlying system is not available.
			GoodResultsMayBeIncomplete = 0x00BA0000, // The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete.
			BadNotTypeDefinition = 0x80C80000, // The provided Nodeid was not a type definition nodeid.
			UncertainReferenceOutOfServer = 0x406C0000, // One of the references to follow in the relative path references to a node in the address space in another server.
			BadTooManyMatches = 0x806D0000, // The requested operation has too many matches to return.
			BadQueryTooComplex = 0x806E0000, // The requested operation requires too many resources in the server.
			BadNoMatch = 0x806F0000, // The requested operation has no match to return.
			BadMaxAgeInvalid = 0x80700000, // The max age parameter is invalid.
			BadHistoryOperationInvalid = 0x80710000, // The history details parameter is not valid.
			BadHistoryOperationUnsupported = 0x80720000, // The server does not support the requested operation.
			BadInvalidTimestampArgument = 0x80BD0000, // The defined timestamp to return was invalid.
			BadWriteNotSupported = 0x80730000, // The server not does support writing the combination of value
			BadTypeMismatch = 0x80740000, // The value supplied for the attribute is not of the same type as the attribute's value.
			BadMethodInvalid = 0x80750000, // The method id does not refer to a method for the specified object.
			BadArgumentsMissing = 0x80760000, // The client did not specify all of the input arguments for the method.
			BadTooManySubscriptions = 0x80770000, // The server has reached its  maximum number of subscriptions.
			BadTooManyPublishRequests = 0x80780000, // The server has reached the maximum number of queued publish requests.
			BadNoSubscription = 0x80790000, // There is no subscription available for this session.
			BadSequenceNumberUnknown = 0x807A0000, // The sequence number is unknown to the server.
			BadMessageNotAvailable = 0x807B0000, // The requested notification message is no longer available.
			BadInsufficientClientProfile = 0x807C0000, // The Client of the current Session does not support one or more Profiles that are necessary for the Subscription.
			BadStateNotActive = 0x80BF0000, // The sub-state machine is not currently active.
			BadTcpServerTooBusy = 0x807D0000, // The server cannot process the request because it is too busy.
			BadTcpMessageTypeInvalid = 0x807E0000, // The type of the message specified in the header invalid.
			BadTcpSecureChannelUnknown = 0x807F0000, // The SecureChannelId and/or TokenId are not currently in use.
			BadTcpMessageTooLarge = 0x80800000, // The size of the message specified in the header is too large.
			BadTcpNotEnoughResources = 0x80810000, // There are not enough resources to process the request.
			BadTcpInternalError = 0x80820000, // An internal error occurred.
			BadTcpEndpointUrlInvalid = 0x80830000, // The Server does not recognize the QueryString specified.
			BadRequestInterrupted = 0x80840000, // The request could not be sent because of a network interruption.
			BadRequestTimeout = 0x80850000, // Timeout occurred while processing the request.
			BadSecureChannelClosed = 0x80860000, // The secure channel has been closed.
			BadSecureChannelTokenUnknown = 0x80870000, // The token has expired or is not recognized.
			BadSequenceNumberInvalid = 0x80880000, // The sequence number is not valid.
			BadProtocolVersionUnsupported = 0x80BE0000, // The applications do not have compatible protocol versions.
			BadConfigurationError = 0x80890000, // There is a problem with the configuration that affects the usefulness of the value.
			BadNotConnected = 0x808A0000, // The variable should receive its value from another variable
			BadDeviceFailure = 0x808B0000, // There has been a failure in the device/data source that generates the value that has affected the value.
			BadSensorFailure = 0x808C0000, // There has been a failure in the sensor from which the value is derived by the device/data source.
			BadOutOfService = 0x808D0000, // The source of the data is not operational.
			BadDeadbandFilterInvalid = 0x808E0000, // The deadband filter is not valid.
			UncertainNoCommunicationLastUsableValue = 0x408F0000, // Communication to the data source has failed. The variable value is the last value that had a good quality.
			UncertainLastUsableValue = 0x40900000, // Whatever was updating this value has stopped doing so.
			UncertainSubstituteValue = 0x40910000, // The value is an operational value that was manually overwritten.
			UncertainInitialValue = 0x40920000, // The value is an initial value for a variable that normally receives its value from another variable.
			UncertainSensorNotAccurate = 0x40930000, // The value is at one of the sensor limits.
			UncertainEngineeringUnitsExceeded = 0x40940000, // The value is outside of the range of values defined for this parameter.
			UncertainSubNormal = 0x40950000, // The value is derived from multiple sources and has less than the required number of Good sources.
			GoodLocalOverride = 0x00960000, // The value has been overridden.
			BadRefreshInProgress = 0x80970000, // This Condition refresh failed
			BadConditionAlreadyDisabled = 0x80980000, // This condition has already been disabled.
			BadConditionAlreadyEnabled = 0x80CC0000, // This condition has already been enabled.
			BadConditionDisabled = 0x80990000, // Property not available
			BadEventIdUnknown = 0x809A0000, // The specified event id is not recognized.
			BadEventNotAcknowledgeable = 0x80BB0000, // The event cannot be acknowledged.
			BadDialogNotActive = 0x80CD0000, // The dialog condition is not active.
			BadDialogResponseInvalid = 0x80CE0000, // The response is not valid for the dialog.
			BadConditionBranchAlreadyAcked = 0x80CF0000, // The condition branch has already been acknowledged.
			BadConditionBranchAlreadyConfirmed = 0x80D00000, // The condition branch has already been confirmed.
			BadConditionAlreadyShelved = 0x80D10000, // The condition has already been shelved.
			BadConditionNotShelved = 0x80D20000, // The condition is not currently shelved.
			BadShelvingTimeOutOfRange = 0x80D30000, // The shelving time not within an acceptable range.
			BadNoData = 0x809B0000, // No data exists for the requested time range or event filter.
			BadBoundNotFound = 0x80D70000, // No data found to provide upper or lower bound value.
			BadBoundNotSupported = 0x80D80000, // The server cannot retrieve a bound for the variable.
			BadDataLost = 0x809D0000, // Data is missing due to collection started/stopped/lost.
			BadDataUnavailable = 0x809E0000, // Expected data is unavailable for the requested time range due to an un-mounted volume
			BadEntryExists = 0x809F0000, // The data or event was not successfully inserted because a matching entry exists.
			BadNoEntryExists = 0x80A00000, // The data or event was not successfully updated because no matching entry exists.
			BadTimestampNotSupported = 0x80A10000, // The client requested history using a timestamp format the server does not support (i.e requested ServerTimestamp when server only supports SourceTimestamp).
			GoodEntryInserted = 0x00A20000, // The data or event was successfully inserted into the historical database.
			GoodEntryReplaced = 0x00A30000, // The data or event field was successfully replaced in the historical database.
			UncertainDataSubNormal = 0x40A40000, // The value is derived from multiple values and has less than the required number of Good values.
			GoodNoData = 0x00A50000, // No data exists for the requested time range or event filter.
			GoodMoreData = 0x00A60000, // The data or event field was successfully replaced in the historical database.
			BadAggregateListMismatch = 0x80D40000, // The requested number of Aggregates does not match the requested number of NodeIds.
			BadAggregateNotSupported = 0x80D50000, // The requested Aggregate is not support by the server.
			BadAggregateInvalidInputs = 0x80D60000, // The aggregate value could not be derived due to invalid data inputs.
			BadAggregateConfigurationRejected = 0x80DA0000, // The aggregate configuration is not valid for specified node.
			GoodDataIgnored = 0x00D90000, // The request pecifies fields which are not valid for the EventType or cannot be saved by the historian.
			GoodCommunicationEvent = 0x00A70000, // The communication layer has raised an event.
			GoodShutdownEvent = 0x00A80000, // The system is shutting down.
			GoodCallAgain = 0x00A90000, // The operation is not finished and needs to be called again.
			GoodNonCriticalTimeout = 0x00AA0000, // A non-critical timeout occurred.
			BadInvalidArgument = 0x80AB0000, // One or more arguments are invalid.
			BadConnectionRejected = 0x80AC0000, // Could not establish a network connection to remote server.
			BadDisconnect = 0x80AD0000, // The server has disconnected from the client.
			BadConnectionClosed = 0x80AE0000, // The network connection has been closed.
			BadInvalidState = 0x80AF0000, // The operation cannot be completed because the object is closed
			BadEndOfStream = 0x80B00000, // Cannot move beyond end of the stream.
			BadNoDataAvailable = 0x80B10000, // No data is currently available for reading from a non-blocking stream.
			BadWaitingForResponse = 0x80B20000, // The asynchronous operation is waiting for a response.
			BadOperationAbandoned = 0x80B30000, // The asynchronous operation was abandoned by the caller.
			BadExpectedStreamToBlock = 0x80B40000, // The stream did not return all data requested (possibly because it is a non-blocking stream).
			BadWouldBlock = 0x80B50000, // Non blocking behaviour is required and the operation would block.
			BadSyntaxError = 0x80B60000, // A value had an invalid syntax.
			BadMaxConnectionsReached = 0x80B70000, // The operation could not be finished because all available connections are in use.
		}

		public enum RequestCode : uint
		{
			ServiceFault = 397,
			TestStackRequest = 410,
			TestStackResponse = 413,
			TestStackExRequest = 416,
			TestStackExResponse = 419,
			FindServersRequest = 422,
			FindServersResponse = 425,
			GetEndpointsRequest = 428,
			GetEndpointsResponse = 431,
			RegisterServerRequest = 437,
			RegisterServerResponse = 440,
			OpenSecureChannelRequest = 446,
			OpenSecureChannelResponse = 449,
			CloseSecureChannelRequest = 452,
			CloseSecureChannelResponse = 455,
			CreateSessionRequest = 461,
			CreateSessionResponse = 464,
			ActivateSessionRequest = 467,
			ActivateSessionResponse = 470,
			CloseSessionRequest = 473,
			CloseSessionResponse = 476,
			CancelRequest = 479,
			CancelResponse = 482,
			AddNodesRequest = 488,
			AddNodesResponse = 491,
			AddReferencesRequest = 494,
			AddReferencesResponse = 497,
			DeleteNodesRequest = 500,
			DeleteNodesResponse = 503,
			DeleteReferencesRequest = 506,
			DeleteReferencesResponse = 509,
			BrowseRequest = 527,
			BrowseResponse = 530,
			BrowseNextRequest = 533,
			BrowseNextResponse = 536,
			TranslateBrowsePathsToNodeIdsRequest = 554,
			TranslateBrowsePathsToNodeIdsResponse = 557,
			RegisterNodesRequest = 560,
			RegisterNodesResponse = 563,
			UnregisterNodesRequest = 566,
			UnregisterNodesResponse = 569,
			QueryFirstRequest = 615,
			QueryFirstResponse = 618,
			QueryNextRequest = 621,
			QueryNextResponse = 624,
			ReadRequest = 631,
			ReadResponse = 634,
			HistoryReadRequest = 664,
			HistoryReadResponse = 667,
			WriteRequest = 673,
			WriteResponse = 676,
			HistoryUpdateRequest = 700,
			HistoryUpdateResponse = 703,
			CallMethodRequest = 706,
			CallRequest = 712,
			CallResponse = 715,
			MonitoredItemCreateRequest = 745,
			CreateMonitoredItemsRequest = 751,
			CreateMonitoredItemsResponse = 754,
			MonitoredItemModifyRequest = 757,
			ModifyMonitoredItemsRequest = 763,
			ModifyMonitoredItemsResponse = 766,
			SetMonitoringModeRequest = 769,
			SetMonitoringModeResponse = 772,
			SetTriggeringRequest = 775,
			SetTriggeringResponse = 778,
			DeleteMonitoredItemsRequest = 781,
			DeleteMonitoredItemsResponse = 784,
			CreateSubscriptionRequest = 787,
			CreateSubscriptionResponse = 790,
			ModifySubscriptionRequest = 793,
			ModifySubscriptionResponse = 796,
			SetPublishingModeRequest = 799,
			SetPublishingModeResponse = 802,
			PublishRequest = 826,
			PublishResponse = 829,
			RepublishRequest = 832,
			RepublishResponse = 835,
			TransferSubscriptionsRequest = 841,
			TransferSubscriptionsResponse = 844,
			DeleteSubscriptionsRequest = 847,
			DeleteSubscriptionsResponse = 850,

			// Server can not generate custom raw responses without requests, so actual responses are always matched by request ids
			// Custom response codes are therefore not needed
			CustomRawResponse = 1001,

			// This and above are reserved for custom message request codes
			CustomRawRequest = 1002,
		}

		public enum UAConst : uint
		{
			Boolean = 1,
			SByte = 2,
			Byte = 3,
			Int16 = 4,
			UInt16 = 5,
			Int32 = 6,
			UInt32 = 7,
			Int64 = 8,
			UInt64 = 9,
			Float = 10,
			Double = 11,
			String = 12,
			DateTime = 13,
			Guid = 14,
			ByteString = 15,
			XmlElement = 16,
			NodeId = 17,
			ExpandedNodeId = 18,
			StatusCode = 19,
			QualifiedName = 20,
			LocalizedText = 21,
			Structure = 22,
			DataValue = 23,
			BaseDataType = 24,
			DiagnosticInfo = 25,
			Number = 26,
			Integer = 27,
			UInteger = 28,
			Enumeration = 29,
			Image = 30,
			References = 31,
			NonHierarchicalReferences = 32,
			HierarchicalReferences = 33,
			HasChild = 34,
			Organizes = 35,
			HasEventSource = 36,
			HasModellingRule = 37,
			HasEncoding = 38,
			HasDescription = 39,
			HasTypeDefinition = 40,
			GeneratesEvent = 41,
			Aggregates = 44,
			HasSubtype = 45,
			HasProperty = 46,
			HasComponent = 47,
			HasNotifier = 48,
			HasOrderedComponent = 49,
			FromState = 51,
			ToState = 52,
			HasCause = 53,
			HasEffect = 54,
			HasHistoricalConfiguration = 56,
			BaseObjectType = 58,
			FolderType = 61,
			BaseVariableType = 62,
			BaseDataVariableType = 63,
			PropertyType = 68,
			DataTypeDescriptionType = 69,
			DataTypeDictionaryType = 72,
			DataTypeSystemType = 75,
			DataTypeEncodingType = 76,
			ModellingRuleType = 77,
			ModellingRule_Mandatory = 78,
			ModellingRule_MandatoryShared = 79,
			ModellingRule_Optional = 80,
			ModellingRule_ExposesItsArray = 83,
			RootFolder = 84,
			ObjectsFolder = 85,
			TypesFolder = 86,
			ViewsFolder = 87,
			ObjectTypesFolder = 88,
			VariableTypesFolder = 89,
			DataTypesFolder = 90,
			ReferenceTypesFolder = 91,
			XmlSchema_TypeSystem = 92,
			OPCBinarySchema_TypeSystem = 93,
			DataTypeDescriptionType_DataTypeVersion = 104,
			DataTypeDescriptionType_DictionaryFragment = 105,
			DataTypeDictionaryType_DataTypeVersion = 106,
			DataTypeDictionaryType_NamespaceUri = 107,
			ModellingRuleType_NamingRule = 111,
			ModellingRule_Mandatory_NamingRule = 112,
			ModellingRule_Optional_NamingRule = 113,
			ModellingRule_ExposesItsArray_NamingRule = 114,
			ModellingRule_MandatoryShared_NamingRule = 116,
			HasSubStateMachine = 117,
			NamingRuleType = 120,
			IdType = 256,
			NodeClass = 257,
			Node = 258,
			Node_Encoding_DefaultXml = 259,
			Node_Encoding_DefaultBinary = 260,
			ObjectNode = 261,
			ObjectNode_Encoding_DefaultXml = 262,
			ObjectNode_Encoding_DefaultBinary = 263,
			ObjectTypeNode = 264,
			ObjectTypeNode_Encoding_DefaultXml = 265,
			ObjectTypeNode_Encoding_DefaultBinary = 266,
			VariableNode = 267,
			VariableNode_Encoding_DefaultXml = 268,
			VariableNode_Encoding_DefaultBinary = 269,
			VariableTypeNode = 270,
			VariableTypeNode_Encoding_DefaultXml = 271,
			VariableTypeNode_Encoding_DefaultBinary = 272,
			ReferenceTypeNode = 273,
			ReferenceTypeNode_Encoding_DefaultXml = 274,
			ReferenceTypeNode_Encoding_DefaultBinary = 275,
			MethodNode = 276,
			MethodNode_Encoding_DefaultXml = 277,
			MethodNode_Encoding_DefaultBinary = 278,
			ViewNode = 279,
			ViewNode_Encoding_DefaultXml = 280,
			ViewNode_Encoding_DefaultBinary = 281,
			DataTypeNode = 282,
			DataTypeNode_Encoding_DefaultXml = 283,
			DataTypeNode_Encoding_DefaultBinary = 284,
			ReferenceNode = 285,
			ReferenceNode_Encoding_DefaultXml = 286,
			ReferenceNode_Encoding_DefaultBinary = 287,
			IntegerId = 288,
			Counter = 289,
			Duration = 290,
			NumericRange = 291,
			Time = 292,
			Date = 293,
			UtcTime = 294,
			LocaleId = 295,
			Argument = 296,
			Argument_Encoding_DefaultXml = 297,
			Argument_Encoding_DefaultBinary = 298,
			StatusResult = 299,
			StatusResult_Encoding_DefaultXml = 300,
			StatusResult_Encoding_DefaultBinary = 301,
			MessageSecurityMode = 302,
			UserTokenType = 303,
			UserTokenPolicy = 304,
			UserTokenPolicy_Encoding_DefaultXml = 305,
			UserTokenPolicy_Encoding_DefaultBinary = 306,
			ApplicationType = 307,
			ApplicationDescription = 308,
			ApplicationDescription_Encoding_DefaultXml = 309,
			ApplicationDescription_Encoding_DefaultBinary = 310,
			ApplicationInstanceCertificate = 311,
			EndpointDescription = 312,
			EndpointDescription_Encoding_DefaultXml = 313,
			EndpointDescription_Encoding_DefaultBinary = 314,
			SecurityTokenRequestType = 315,
			UserIdentityToken = 316,
			UserIdentityToken_Encoding_DefaultXml = 317,
			UserIdentityToken_Encoding_DefaultBinary = 318,
			AnonymousIdentityToken = 319,
			AnonymousIdentityToken_Encoding_DefaultXml = 320,
			AnonymousIdentityToken_Encoding_DefaultBinary = 321,
			UserNameIdentityToken = 322,
			UserNameIdentityToken_Encoding_DefaultXml = 323,
			UserNameIdentityToken_Encoding_DefaultBinary = 324,
			X509IdentityToken = 325,
			X509IdentityToken_Encoding_DefaultXml = 326,
			X509IdentityToken_Encoding_DefaultBinary = 327,
			EndpointConfiguration = 331,
			EndpointConfiguration_Encoding_DefaultXml = 332,
			EndpointConfiguration_Encoding_DefaultBinary = 333,
			ComplianceLevel = 334,
			SupportedProfile = 335,
			SupportedProfile_Encoding_DefaultXml = 336,
			SupportedProfile_Encoding_DefaultBinary = 337,
			BuildInfo = 338,
			BuildInfo_Encoding_DefaultXml = 339,
			BuildInfo_Encoding_DefaultBinary = 340,
			SoftwareCertificate = 341,
			SoftwareCertificate_Encoding_DefaultXml = 342,
			SoftwareCertificate_Encoding_DefaultBinary = 343,
			SignedSoftwareCertificate = 344,
			SignedSoftwareCertificate_Encoding_DefaultXml = 345,
			SignedSoftwareCertificate_Encoding_DefaultBinary = 346,
			AttributeWriteMask = 347,
			NodeAttributesMask = 348,
			NodeAttributes = 349,
			NodeAttributes_Encoding_DefaultXml = 350,
			NodeAttributes_Encoding_DefaultBinary = 351,
			ObjectAttributes = 352,
			ObjectAttributes_Encoding_DefaultXml = 353,
			ObjectAttributes_Encoding_DefaultBinary = 354,
			VariableAttributes = 355,
			VariableAttributes_Encoding_DefaultXml = 356,
			VariableAttributes_Encoding_DefaultBinary = 357,
			MethodAttributes = 358,
			MethodAttributes_Encoding_DefaultXml = 359,
			MethodAttributes_Encoding_DefaultBinary = 360,
			ObjectTypeAttributes = 361,
			ObjectTypeAttributes_Encoding_DefaultXml = 362,
			ObjectTypeAttributes_Encoding_DefaultBinary = 363,
			VariableTypeAttributes = 364,
			VariableTypeAttributes_Encoding_DefaultXml = 365,
			VariableTypeAttributes_Encoding_DefaultBinary = 366,
			ReferenceTypeAttributes = 367,
			ReferenceTypeAttributes_Encoding_DefaultXml = 368,
			ReferenceTypeAttributes_Encoding_DefaultBinary = 369,
			DataTypeAttributes = 370,
			DataTypeAttributes_Encoding_DefaultXml = 371,
			DataTypeAttributes_Encoding_DefaultBinary = 372,
			ViewAttributes = 373,
			ViewAttributes_Encoding_DefaultXml = 374,
			ViewAttributes_Encoding_DefaultBinary = 375,
			AddNodesItem = 376,
			AddNodesItem_Encoding_DefaultXml = 377,
			AddNodesItem_Encoding_DefaultBinary = 378,
			AddReferencesItem = 379,
			AddReferencesItem_Encoding_DefaultXml = 380,
			AddReferencesItem_Encoding_DefaultBinary = 381,
			DeleteNodesItem = 382,
			DeleteNodesItem_Encoding_DefaultXml = 383,
			DeleteNodesItem_Encoding_DefaultBinary = 384,
			DeleteReferencesItem = 385,
			DeleteReferencesItem_Encoding_DefaultXml = 386,
			DeleteReferencesItem_Encoding_DefaultBinary = 387,
			SessionAuthenticationToken = 388,
			RequestHeader = 389,
			RequestHeader_Encoding_DefaultXml = 390,
			RequestHeader_Encoding_DefaultBinary = 391,
			ResponseHeader = 392,
			ResponseHeader_Encoding_DefaultXml = 393,
			ResponseHeader_Encoding_DefaultBinary = 394,
			ServiceFault = 395,
			ServiceFault_Encoding_DefaultXml = 396,
			ServiceFault_Encoding_DefaultBinary = 397,
			EnumeratedTestType = 398,
			ScalarTestType = 399,
			ScalarTestType_Encoding_DefaultXml = 400,
			ScalarTestType_Encoding_DefaultBinary = 401,
			ArrayTestType = 402,
			ArrayTestType_Encoding_DefaultXml = 403,
			ArrayTestType_Encoding_DefaultBinary = 404,
			CompositeTestType = 405,
			CompositeTestType_Encoding_DefaultXml = 406,
			CompositeTestType_Encoding_DefaultBinary = 407,
			TestStackRequest = 408,
			TestStackRequest_Encoding_DefaultXml = 409,
			TestStackRequest_Encoding_DefaultBinary = 410,
			TestStackResponse = 411,
			TestStackResponse_Encoding_DefaultXml = 412,
			TestStackResponse_Encoding_DefaultBinary = 413,
			TestStackExRequest = 414,
			TestStackExRequest_Encoding_DefaultXml = 415,
			TestStackExRequest_Encoding_DefaultBinary = 416,
			TestStackExResponse = 417,
			TestStackExResponse_Encoding_DefaultXml = 418,
			TestStackExResponse_Encoding_DefaultBinary = 419,
			FindServersRequest = 420,
			FindServersRequest_Encoding_DefaultXml = 421,
			FindServersRequest_Encoding_DefaultBinary = 422,
			FindServersResponse = 423,
			FindServersResponse_Encoding_DefaultXml = 424,
			FindServersResponse_Encoding_DefaultBinary = 425,
			GetEndpointsRequest = 426,
			GetEndpointsRequest_Encoding_DefaultXml = 427,
			GetEndpointsRequest_Encoding_DefaultBinary = 428,
			GetEndpointsResponse = 429,
			GetEndpointsResponse_Encoding_DefaultXml = 430,
			GetEndpointsResponse_Encoding_DefaultBinary = 431,
			RegisteredServer = 432,
			RegisteredServer_Encoding_DefaultXml = 433,
			RegisteredServer_Encoding_DefaultBinary = 434,
			RegisterServerRequest = 435,
			RegisterServerRequest_Encoding_DefaultXml = 436,
			RegisterServerRequest_Encoding_DefaultBinary = 437,
			RegisterServerResponse = 438,
			RegisterServerResponse_Encoding_DefaultXml = 439,
			RegisterServerResponse_Encoding_DefaultBinary = 440,
			ChannelSecurityToken = 441,
			ChannelSecurityToken_Encoding_DefaultXml = 442,
			ChannelSecurityToken_Encoding_DefaultBinary = 443,
			OpenSecureChannelRequest = 444,
			OpenSecureChannelRequest_Encoding_DefaultXml = 445,
			OpenSecureChannelRequest_Encoding_DefaultBinary = 446,
			OpenSecureChannelResponse = 447,
			OpenSecureChannelResponse_Encoding_DefaultXml = 448,
			OpenSecureChannelResponse_Encoding_DefaultBinary = 449,
			CloseSecureChannelRequest = 450,
			CloseSecureChannelRequest_Encoding_DefaultXml = 451,
			CloseSecureChannelRequest_Encoding_DefaultBinary = 452,
			CloseSecureChannelResponse = 453,
			CloseSecureChannelResponse_Encoding_DefaultXml = 454,
			CloseSecureChannelResponse_Encoding_DefaultBinary = 455,
			SignatureData = 456,
			SignatureData_Encoding_DefaultXml = 457,
			SignatureData_Encoding_DefaultBinary = 458,
			CreateSessionRequest = 459,
			CreateSessionRequest_Encoding_DefaultXml = 460,
			CreateSessionRequest_Encoding_DefaultBinary = 461,
			CreateSessionResponse = 462,
			CreateSessionResponse_Encoding_DefaultXml = 463,
			CreateSessionResponse_Encoding_DefaultBinary = 464,
			ActivateSessionRequest = 465,
			ActivateSessionRequest_Encoding_DefaultXml = 466,
			ActivateSessionRequest_Encoding_DefaultBinary = 467,
			ActivateSessionResponse = 468,
			ActivateSessionResponse_Encoding_DefaultXml = 469,
			ActivateSessionResponse_Encoding_DefaultBinary = 470,
			CloseSessionRequest = 471,
			CloseSessionRequest_Encoding_DefaultXml = 472,
			CloseSessionRequest_Encoding_DefaultBinary = 473,
			CloseSessionResponse = 474,
			CloseSessionResponse_Encoding_DefaultXml = 475,
			CloseSessionResponse_Encoding_DefaultBinary = 476,
			CancelRequest = 477,
			CancelRequest_Encoding_DefaultXml = 478,
			CancelRequest_Encoding_DefaultBinary = 479,
			CancelResponse = 480,
			CancelResponse_Encoding_DefaultXml = 481,
			CancelResponse_Encoding_DefaultBinary = 482,
			AddNodesResult = 483,
			AddNodesResult_Encoding_DefaultXml = 484,
			AddNodesResult_Encoding_DefaultBinary = 485,
			AddNodesRequest = 486,
			AddNodesRequest_Encoding_DefaultXml = 487,
			AddNodesRequest_Encoding_DefaultBinary = 488,
			AddNodesResponse = 489,
			AddNodesResponse_Encoding_DefaultXml = 490,
			AddNodesResponse_Encoding_DefaultBinary = 491,
			AddReferencesRequest = 492,
			AddReferencesRequest_Encoding_DefaultXml = 493,
			AddReferencesRequest_Encoding_DefaultBinary = 494,
			AddReferencesResponse = 495,
			AddReferencesResponse_Encoding_DefaultXml = 496,
			AddReferencesResponse_Encoding_DefaultBinary = 497,
			DeleteNodesRequest = 498,
			DeleteNodesRequest_Encoding_DefaultXml = 499,
			DeleteNodesRequest_Encoding_DefaultBinary = 500,
			DeleteNodesResponse = 501,
			DeleteNodesResponse_Encoding_DefaultXml = 502,
			DeleteNodesResponse_Encoding_DefaultBinary = 503,
			DeleteReferencesRequest = 504,
			DeleteReferencesRequest_Encoding_DefaultXml = 505,
			DeleteReferencesRequest_Encoding_DefaultBinary = 506,
			DeleteReferencesResponse = 507,
			DeleteReferencesResponse_Encoding_DefaultXml = 508,
			DeleteReferencesResponse_Encoding_DefaultBinary = 509,
			BrowseDirection = 510,
			ViewDescription = 511,
			ViewDescription_Encoding_DefaultXml = 512,
			ViewDescription_Encoding_DefaultBinary = 513,
			BrowseDescription = 514,
			BrowseDescription_Encoding_DefaultXml = 515,
			BrowseDescription_Encoding_DefaultBinary = 516,
			BrowseResultMask = 517,
			ReferenceDescription = 518,
			ReferenceDescription_Encoding_DefaultXml = 519,
			ReferenceDescription_Encoding_DefaultBinary = 520,
			ContinuationPoint = 521,
			BrowseResult = 522,
			BrowseResult_Encoding_DefaultXml = 523,
			BrowseResult_Encoding_DefaultBinary = 524,
			BrowseRequest = 525,
			BrowseRequest_Encoding_DefaultXml = 526,
			BrowseRequest_Encoding_DefaultBinary = 527,
			BrowseResponse = 528,
			BrowseResponse_Encoding_DefaultXml = 529,
			BrowseResponse_Encoding_DefaultBinary = 530,
			BrowseNextRequest = 531,
			BrowseNextRequest_Encoding_DefaultXml = 532,
			BrowseNextRequest_Encoding_DefaultBinary = 533,
			BrowseNextResponse = 534,
			BrowseNextResponse_Encoding_DefaultXml = 535,
			BrowseNextResponse_Encoding_DefaultBinary = 536,
			RelativePathElement = 537,
			RelativePathElement_Encoding_DefaultXml = 538,
			RelativePathElement_Encoding_DefaultBinary = 539,
			RelativePath = 540,
			RelativePath_Encoding_DefaultXml = 541,
			RelativePath_Encoding_DefaultBinary = 542,
			BrowsePath = 543,
			BrowsePath_Encoding_DefaultXml = 544,
			BrowsePath_Encoding_DefaultBinary = 545,
			BrowsePathTarget = 546,
			BrowsePathTarget_Encoding_DefaultXml = 547,
			BrowsePathTarget_Encoding_DefaultBinary = 548,
			BrowsePathResult = 549,
			BrowsePathResult_Encoding_DefaultXml = 550,
			BrowsePathResult_Encoding_DefaultBinary = 551,
			TranslateBrowsePathsToNodeIdsRequest = 552,
			TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultXml = 553,
			TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary = 554,
			TranslateBrowsePathsToNodeIdsResponse = 555,
			TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultXml = 556,
			TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultBinary = 557,
			RegisterNodesRequest = 558,
			RegisterNodesRequest_Encoding_DefaultXml = 559,
			RegisterNodesRequest_Encoding_DefaultBinary = 560,
			RegisterNodesResponse = 561,
			RegisterNodesResponse_Encoding_DefaultXml = 562,
			RegisterNodesResponse_Encoding_DefaultBinary = 563,
			UnregisterNodesRequest = 564,
			UnregisterNodesRequest_Encoding_DefaultXml = 565,
			UnregisterNodesRequest_Encoding_DefaultBinary = 566,
			UnregisterNodesResponse = 567,
			UnregisterNodesResponse_Encoding_DefaultXml = 568,
			UnregisterNodesResponse_Encoding_DefaultBinary = 569,
			QueryDataDescription = 570,
			QueryDataDescription_Encoding_DefaultXml = 571,
			QueryDataDescription_Encoding_DefaultBinary = 572,
			NodeTypeDescription = 573,
			NodeTypeDescription_Encoding_DefaultXml = 574,
			NodeTypeDescription_Encoding_DefaultBinary = 575,
			FilterOperator = 576,
			QueryDataSet = 577,
			QueryDataSet_Encoding_DefaultXml = 578,
			QueryDataSet_Encoding_DefaultBinary = 579,
			NodeReference = 580,
			NodeReference_Encoding_DefaultXml = 581,
			NodeReference_Encoding_DefaultBinary = 582,
			ContentFilterElement = 583,
			ContentFilterElement_Encoding_DefaultXml = 584,
			ContentFilterElement_Encoding_DefaultBinary = 585,
			ContentFilter = 586,
			ContentFilter_Encoding_DefaultXml = 587,
			ContentFilter_Encoding_DefaultBinary = 588,
			FilterOperand = 589,
			FilterOperand_Encoding_DefaultXml = 590,
			FilterOperand_Encoding_DefaultBinary = 591,
			ElementOperand = 592,
			ElementOperand_Encoding_DefaultXml = 593,
			ElementOperand_Encoding_DefaultBinary = 594,
			LiteralOperand = 595,
			LiteralOperand_Encoding_DefaultXml = 596,
			LiteralOperand_Encoding_DefaultBinary = 597,
			AttributeOperand = 598,
			AttributeOperand_Encoding_DefaultXml = 599,
			AttributeOperand_Encoding_DefaultBinary = 600,
			SimpleAttributeOperand = 601,
			SimpleAttributeOperand_Encoding_DefaultXml = 602,
			SimpleAttributeOperand_Encoding_DefaultBinary = 603,
			ContentFilterElementResult = 604,
			ContentFilterElementResult_Encoding_DefaultXml = 605,
			ContentFilterElementResult_Encoding_DefaultBinary = 606,
			ContentFilterResult = 607,
			ContentFilterResult_Encoding_DefaultXml = 608,
			ContentFilterResult_Encoding_DefaultBinary = 609,
			ParsingResult = 610,
			ParsingResult_Encoding_DefaultXml = 611,
			ParsingResult_Encoding_DefaultBinary = 612,
			QueryFirstRequest = 613,
			QueryFirstRequest_Encoding_DefaultXml = 614,
			QueryFirstRequest_Encoding_DefaultBinary = 615,
			QueryFirstResponse = 616,
			QueryFirstResponse_Encoding_DefaultXml = 617,
			QueryFirstResponse_Encoding_DefaultBinary = 618,
			QueryNextRequest = 619,
			QueryNextRequest_Encoding_DefaultXml = 620,
			QueryNextRequest_Encoding_DefaultBinary = 621,
			QueryNextResponse = 622,
			QueryNextResponse_Encoding_DefaultXml = 623,
			QueryNextResponse_Encoding_DefaultBinary = 624,
			TimestampsToReturn = 625,
			ReadValueId = 626,
			ReadValueId_Encoding_DefaultXml = 627,
			ReadValueId_Encoding_DefaultBinary = 628,
			ReadRequest = 629,
			ReadRequest_Encoding_DefaultXml = 630,
			ReadRequest_Encoding_DefaultBinary = 631,
			ReadResponse = 632,
			ReadResponse_Encoding_DefaultXml = 633,
			ReadResponse_Encoding_DefaultBinary = 634,
			HistoryReadValueId = 635,
			HistoryReadValueId_Encoding_DefaultXml = 636,
			HistoryReadValueId_Encoding_DefaultBinary = 637,
			HistoryReadResult = 638,
			HistoryReadResult_Encoding_DefaultXml = 639,
			HistoryReadResult_Encoding_DefaultBinary = 640,
			HistoryReadDetails = 641,
			HistoryReadDetails_Encoding_DefaultXml = 642,
			HistoryReadDetails_Encoding_DefaultBinary = 643,
			ReadEventDetails = 644,
			ReadEventDetails_Encoding_DefaultXml = 645,
			ReadEventDetails_Encoding_DefaultBinary = 646,
			ReadRawModifiedDetails = 647,
			ReadRawModifiedDetails_Encoding_DefaultXml = 648,
			ReadRawModifiedDetails_Encoding_DefaultBinary = 649,
			ReadProcessedDetails = 650,
			ReadProcessedDetails_Encoding_DefaultXml = 651,
			ReadProcessedDetails_Encoding_DefaultBinary = 652,
			ReadAtTimeDetails = 653,
			ReadAtTimeDetails_Encoding_DefaultXml = 654,
			ReadAtTimeDetails_Encoding_DefaultBinary = 655,
			HistoryData = 656,
			HistoryData_Encoding_DefaultXml = 657,
			HistoryData_Encoding_DefaultBinary = 658,
			HistoryEvent = 659,
			HistoryEvent_Encoding_DefaultXml = 660,
			HistoryEvent_Encoding_DefaultBinary = 661,
			HistoryReadRequest = 662,
			HistoryReadRequest_Encoding_DefaultXml = 663,
			HistoryReadRequest_Encoding_DefaultBinary = 664,
			HistoryReadResponse = 665,
			HistoryReadResponse_Encoding_DefaultXml = 666,
			HistoryReadResponse_Encoding_DefaultBinary = 667,
			WriteValue = 668,
			WriteValue_Encoding_DefaultXml = 669,
			WriteValue_Encoding_DefaultBinary = 670,
			WriteRequest = 671,
			WriteRequest_Encoding_DefaultXml = 672,
			WriteRequest_Encoding_DefaultBinary = 673,
			WriteResponse = 674,
			WriteResponse_Encoding_DefaultXml = 675,
			WriteResponse_Encoding_DefaultBinary = 676,
			HistoryUpdateDetails = 677,
			HistoryUpdateDetails_Encoding_DefaultXml = 678,
			HistoryUpdateDetails_Encoding_DefaultBinary = 679,
			UpdateDataDetails = 680,
			UpdateDataDetails_Encoding_DefaultXml = 681,
			UpdateDataDetails_Encoding_DefaultBinary = 682,
			UpdateEventDetails = 683,
			UpdateEventDetails_Encoding_DefaultXml = 684,
			UpdateEventDetails_Encoding_DefaultBinary = 685,
			DeleteRawModifiedDetails = 686,
			DeleteRawModifiedDetails_Encoding_DefaultXml = 687,
			DeleteRawModifiedDetails_Encoding_DefaultBinary = 688,
			DeleteAtTimeDetails = 689,
			DeleteAtTimeDetails_Encoding_DefaultXml = 690,
			DeleteAtTimeDetails_Encoding_DefaultBinary = 691,
			DeleteEventDetails = 692,
			DeleteEventDetails_Encoding_DefaultXml = 693,
			DeleteEventDetails_Encoding_DefaultBinary = 694,
			HistoryUpdateResult = 695,
			HistoryUpdateResult_Encoding_DefaultXml = 696,
			HistoryUpdateResult_Encoding_DefaultBinary = 697,
			HistoryUpdateRequest = 698,
			HistoryUpdateRequest_Encoding_DefaultXml = 699,
			HistoryUpdateRequest_Encoding_DefaultBinary = 700,
			HistoryUpdateResponse = 701,
			HistoryUpdateResponse_Encoding_DefaultXml = 702,
			HistoryUpdateResponse_Encoding_DefaultBinary = 703,
			CallMethodRequest = 704,
			CallMethodRequest_Encoding_DefaultXml = 705,
			CallMethodRequest_Encoding_DefaultBinary = 706,
			CallMethodResult = 707,
			CallMethodResult_Encoding_DefaultXml = 708,
			CallMethodResult_Encoding_DefaultBinary = 709,
			CallRequest = 710,
			CallRequest_Encoding_DefaultXml = 711,
			CallRequest_Encoding_DefaultBinary = 712,
			CallResponse = 713,
			CallResponse_Encoding_DefaultXml = 714,
			CallResponse_Encoding_DefaultBinary = 715,
			MonitoringMode = 716,
			DataChangeTrigger = 717,
			DeadbandType = 718,
			MonitoringFilter = 719,
			MonitoringFilter_Encoding_DefaultXml = 720,
			MonitoringFilter_Encoding_DefaultBinary = 721,
			DataChangeFilter = 722,
			DataChangeFilter_Encoding_DefaultXml = 723,
			DataChangeFilter_Encoding_DefaultBinary = 724,
			EventFilter = 725,
			EventFilter_Encoding_DefaultXml = 726,
			EventFilter_Encoding_DefaultBinary = 727,
			AggregateFilter = 728,
			AggregateFilter_Encoding_DefaultXml = 729,
			AggregateFilter_Encoding_DefaultBinary = 730,
			MonitoringFilterResult = 731,
			MonitoringFilterResult_Encoding_DefaultXml = 732,
			MonitoringFilterResult_Encoding_DefaultBinary = 733,
			EventFilterResult = 734,
			EventFilterResult_Encoding_DefaultXml = 735,
			EventFilterResult_Encoding_DefaultBinary = 736,
			AggregateFilterResult = 737,
			AggregateFilterResult_Encoding_DefaultXml = 738,
			AggregateFilterResult_Encoding_DefaultBinary = 739,
			MonitoringParameters = 740,
			MonitoringParameters_Encoding_DefaultXml = 741,
			MonitoringParameters_Encoding_DefaultBinary = 742,
			MonitoredItemCreateRequest = 743,
			MonitoredItemCreateRequest_Encoding_DefaultXml = 744,
			MonitoredItemCreateRequest_Encoding_DefaultBinary = 745,
			MonitoredItemCreateResult = 746,
			MonitoredItemCreateResult_Encoding_DefaultXml = 747,
			MonitoredItemCreateResult_Encoding_DefaultBinary = 748,
			CreateMonitoredItemsRequest = 749,
			CreateMonitoredItemsRequest_Encoding_DefaultXml = 750,
			CreateMonitoredItemsRequest_Encoding_DefaultBinary = 751,
			CreateMonitoredItemsResponse = 752,
			CreateMonitoredItemsResponse_Encoding_DefaultXml = 753,
			CreateMonitoredItemsResponse_Encoding_DefaultBinary = 754,
			MonitoredItemModifyRequest = 755,
			MonitoredItemModifyRequest_Encoding_DefaultXml = 756,
			MonitoredItemModifyRequest_Encoding_DefaultBinary = 757,
			MonitoredItemModifyResult = 758,
			MonitoredItemModifyResult_Encoding_DefaultXml = 759,
			MonitoredItemModifyResult_Encoding_DefaultBinary = 760,
			ModifyMonitoredItemsRequest = 761,
			ModifyMonitoredItemsRequest_Encoding_DefaultXml = 762,
			ModifyMonitoredItemsRequest_Encoding_DefaultBinary = 763,
			ModifyMonitoredItemsResponse = 764,
			ModifyMonitoredItemsResponse_Encoding_DefaultXml = 765,
			ModifyMonitoredItemsResponse_Encoding_DefaultBinary = 766,
			SetMonitoringModeRequest = 767,
			SetMonitoringModeRequest_Encoding_DefaultXml = 768,
			SetMonitoringModeRequest_Encoding_DefaultBinary = 769,
			SetMonitoringModeResponse = 770,
			SetMonitoringModeResponse_Encoding_DefaultXml = 771,
			SetMonitoringModeResponse_Encoding_DefaultBinary = 772,
			SetTriggeringRequest = 773,
			SetTriggeringRequest_Encoding_DefaultXml = 774,
			SetTriggeringRequest_Encoding_DefaultBinary = 775,
			SetTriggeringResponse = 776,
			SetTriggeringResponse_Encoding_DefaultXml = 777,
			SetTriggeringResponse_Encoding_DefaultBinary = 778,
			DeleteMonitoredItemsRequest = 779,
			DeleteMonitoredItemsRequest_Encoding_DefaultXml = 780,
			DeleteMonitoredItemsRequest_Encoding_DefaultBinary = 781,
			DeleteMonitoredItemsResponse = 782,
			DeleteMonitoredItemsResponse_Encoding_DefaultXml = 783,
			DeleteMonitoredItemsResponse_Encoding_DefaultBinary = 784,
			CreateSubscriptionRequest = 785,
			CreateSubscriptionRequest_Encoding_DefaultXml = 786,
			CreateSubscriptionRequest_Encoding_DefaultBinary = 787,
			CreateSubscriptionResponse = 788,
			CreateSubscriptionResponse_Encoding_DefaultXml = 789,
			CreateSubscriptionResponse_Encoding_DefaultBinary = 790,
			ModifySubscriptionRequest = 791,
			ModifySubscriptionRequest_Encoding_DefaultXml = 792,
			ModifySubscriptionRequest_Encoding_DefaultBinary = 793,
			ModifySubscriptionResponse = 794,
			ModifySubscriptionResponse_Encoding_DefaultXml = 795,
			ModifySubscriptionResponse_Encoding_DefaultBinary = 796,
			SetPublishingModeRequest = 797,
			SetPublishingModeRequest_Encoding_DefaultXml = 798,
			SetPublishingModeRequest_Encoding_DefaultBinary = 799,
			SetPublishingModeResponse = 800,
			SetPublishingModeResponse_Encoding_DefaultXml = 801,
			SetPublishingModeResponse_Encoding_DefaultBinary = 802,
			NotificationMessage = 803,
			NotificationMessage_Encoding_DefaultXml = 804,
			NotificationMessage_Encoding_DefaultBinary = 805,
			MonitoredItemNotification = 806,
			MonitoredItemNotification_Encoding_DefaultXml = 807,
			MonitoredItemNotification_Encoding_DefaultBinary = 808,
			DataChangeNotification = 809,
			DataChangeNotification_Encoding_DefaultXml = 810,
			DataChangeNotification_Encoding_DefaultBinary = 811,
			StatusChangeNotification = 818,
			StatusChangeNotification_Encoding_DefaultXml = 819,
			StatusChangeNotification_Encoding_DefaultBinary = 820,
			SubscriptionAcknowledgement = 821,
			SubscriptionAcknowledgement_Encoding_DefaultXml = 822,
			SubscriptionAcknowledgement_Encoding_DefaultBinary = 823,
			PublishRequest = 824,
			PublishRequest_Encoding_DefaultXml = 825,
			PublishRequest_Encoding_DefaultBinary = 826,
			PublishResponse = 827,
			PublishResponse_Encoding_DefaultXml = 828,
			PublishResponse_Encoding_DefaultBinary = 829,
			RepublishRequest = 830,
			RepublishRequest_Encoding_DefaultXml = 831,
			RepublishRequest_Encoding_DefaultBinary = 832,
			RepublishResponse = 833,
			RepublishResponse_Encoding_DefaultXml = 834,
			RepublishResponse_Encoding_DefaultBinary = 835,
			TransferResult = 836,
			TransferResult_Encoding_DefaultXml = 837,
			TransferResult_Encoding_DefaultBinary = 838,
			TransferSubscriptionsRequest = 839,
			TransferSubscriptionsRequest_Encoding_DefaultXml = 840,
			TransferSubscriptionsRequest_Encoding_DefaultBinary = 841,
			TransferSubscriptionsResponse = 842,
			TransferSubscriptionsResponse_Encoding_DefaultXml = 843,
			TransferSubscriptionsResponse_Encoding_DefaultBinary = 844,
			DeleteSubscriptionsRequest = 845,
			DeleteSubscriptionsRequest_Encoding_DefaultXml = 846,
			DeleteSubscriptionsRequest_Encoding_DefaultBinary = 847,
			DeleteSubscriptionsResponse = 848,
			DeleteSubscriptionsResponse_Encoding_DefaultXml = 849,
			DeleteSubscriptionsResponse_Encoding_DefaultBinary = 850,
			RedundancySupport = 851,
			ServerState = 852,
			RedundantServerDataType = 853,
			RedundantServerDataType_Encoding_DefaultXml = 854,
			RedundantServerDataType_Encoding_DefaultBinary = 855,
			SamplingIntervalDiagnosticsDataType = 856,
			SamplingIntervalDiagnosticsDataType_Encoding_DefaultXml = 857,
			SamplingIntervalDiagnosticsDataType_Encoding_DefaultBinary = 858,
			ServerDiagnosticsSummaryDataType = 859,
			ServerDiagnosticsSummaryDataType_Encoding_DefaultXml = 860,
			ServerDiagnosticsSummaryDataType_Encoding_DefaultBinary = 861,
			ServerStatusDataType = 862,
			ServerStatusDataType_Encoding_DefaultXml = 863,
			ServerStatusDataType_Encoding_DefaultBinary = 864,
			SessionDiagnosticsDataType = 865,
			SessionDiagnosticsDataType_Encoding_DefaultXml = 866,
			SessionDiagnosticsDataType_Encoding_DefaultBinary = 867,
			SessionSecurityDiagnosticsDataType = 868,
			SessionSecurityDiagnosticsDataType_Encoding_DefaultXml = 869,
			SessionSecurityDiagnosticsDataType_Encoding_DefaultBinary = 870,
			ServiceCounterDataType = 871,
			ServiceCounterDataType_Encoding_DefaultXml = 872,
			ServiceCounterDataType_Encoding_DefaultBinary = 873,
			SubscriptionDiagnosticsDataType = 874,
			SubscriptionDiagnosticsDataType_Encoding_DefaultXml = 875,
			SubscriptionDiagnosticsDataType_Encoding_DefaultBinary = 876,
			ModelChangeStructureDataType = 877,
			ModelChangeStructureDataType_Encoding_DefaultXml = 878,
			ModelChangeStructureDataType_Encoding_DefaultBinary = 879,
			Range = 884,
			Range_Encoding_DefaultXml = 885,
			Range_Encoding_DefaultBinary = 886,
			EUInformation = 887,
			EUInformation_Encoding_DefaultXml = 888,
			EUInformation_Encoding_DefaultBinary = 889,
			ExceptionDeviationFormat = 890,
			Annotation = 891,
			Annotation_Encoding_DefaultXml = 892,
			Annotation_Encoding_DefaultBinary = 893,
			ProgramDiagnosticDataType = 894,
			ProgramDiagnosticDataType_Encoding_DefaultXml = 895,
			ProgramDiagnosticDataType_Encoding_DefaultBinary = 896,
			SemanticChangeStructureDataType = 897,
			SemanticChangeStructureDataType_Encoding_DefaultXml = 898,
			SemanticChangeStructureDataType_Encoding_DefaultBinary = 899,
			EventNotificationList = 914,
			EventNotificationList_Encoding_DefaultXml = 915,
			EventNotificationList_Encoding_DefaultBinary = 916,
			EventFieldList = 917,
			EventFieldList_Encoding_DefaultXml = 918,
			EventFieldList_Encoding_DefaultBinary = 919,
			HistoryEventFieldList = 920,
			HistoryEventFieldList_Encoding_DefaultXml = 921,
			HistoryEventFieldList_Encoding_DefaultBinary = 922,
			HistoryUpdateEventResult = 929,
			HistoryUpdateEventResult_Encoding_DefaultXml = 930,
			HistoryUpdateEventResult_Encoding_DefaultBinary = 931,
			IssuedIdentityToken = 938,
			IssuedIdentityToken_Encoding_DefaultXml = 939,
			IssuedIdentityToken_Encoding_DefaultBinary = 940,
			NotificationData = 945,
			NotificationData_Encoding_DefaultXml = 946,
			NotificationData_Encoding_DefaultBinary = 947,
			AggregateConfiguration = 948,
			AggregateConfiguration_Encoding_DefaultXml = 949,
			AggregateConfiguration_Encoding_DefaultBinary = 950,
			ImageBMP = 2000,
			ImageGIF = 2001,
			ImageJPG = 2002,
			ImagePNG = 2003,
			ServerType = 2004,
			ServerType_ServerArray = 2005,
			ServerType_NamespaceArray = 2006,
			ServerType_ServerStatus = 2007,
			ServerType_ServiceLevel = 2008,
			ServerType_ServerCapabilities = 2009,
			ServerType_ServerDiagnostics = 2010,
			ServerType_VendorServerInfo = 2011,
			ServerType_ServerRedundancy = 2012,
			ServerCapabilitiesType = 2013,
			ServerCapabilitiesType_ServerProfileArray = 2014,
			ServerCapabilitiesType_LocaleIdArray = 2016,
			ServerCapabilitiesType_MinSupportedSampleRate = 2017,
			ServerCapabilitiesType_ModellingRules = 2019,
			ServerDiagnosticsType = 2020,
			ServerDiagnosticsType_ServerDiagnosticsSummary = 2021,
			ServerDiagnosticsType_SamplingIntervalDiagnosticsArray = 2022,
			ServerDiagnosticsType_SubscriptionDiagnosticsArray = 2023,
			ServerDiagnosticsType_EnabledFlag = 2025,
			SessionsDiagnosticsSummaryType = 2026,
			SessionsDiagnosticsSummaryType_SessionDiagnosticsArray = 2027,
			SessionsDiagnosticsSummaryType_SessionSecurityDiagnosticsArray = 2028,
			SessionDiagnosticsObjectType = 2029,
			SessionDiagnosticsObjectType_SessionDiagnostics = 2030,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics = 2031,
			SessionDiagnosticsObjectType_SubscriptionDiagnosticsArray = 2032,
			VendorServerInfoType = 2033,
			ServerRedundancyType = 2034,
			ServerRedundancyType_RedundancySupport = 2035,
			TransparentRedundancyType = 2036,
			TransparentRedundancyType_CurrentServerId = 2037,
			TransparentRedundancyType_RedundantServerArray = 2038,
			NonTransparentRedundancyType = 2039,
			NonTransparentRedundancyType_ServerUriArray = 2040,
			BaseEventType = 2041,
			BaseEventType_EventId = 2042,
			BaseEventType_EventType = 2043,
			BaseEventType_SourceNode = 2044,
			BaseEventType_SourceName = 2045,
			BaseEventType_Time = 2046,
			BaseEventType_ReceiveTime = 2047,
			BaseEventType_Message = 2050,
			BaseEventType_Severity = 2051,
			AuditEventType = 2052,
			AuditEventType_ActionTimeStamp = 2053,
			AuditEventType_Status = 2054,
			AuditEventType_ServerId = 2055,
			AuditEventType_ClientAuditEntryId = 2056,
			AuditEventType_ClientUserId = 2057,
			AuditSecurityEventType = 2058,
			AuditChannelEventType = 2059,
			AuditOpenSecureChannelEventType = 2060,
			AuditOpenSecureChannelEventType_ClientCertificate = 2061,
			AuditOpenSecureChannelEventType_RequestType = 2062,
			AuditOpenSecureChannelEventType_SecurityPolicyUri = 2063,
			AuditOpenSecureChannelEventType_SecurityMode = 2065,
			AuditOpenSecureChannelEventType_RequestedLifetime = 2066,
			AuditSessionEventType = 2069,
			AuditSessionEventType_SessionId = 2070,
			AuditCreateSessionEventType = 2071,
			AuditCreateSessionEventType_SecureChannelId = 2072,
			AuditCreateSessionEventType_ClientCertificate = 2073,
			AuditCreateSessionEventType_RevisedSessionTimeout = 2074,
			AuditActivateSessionEventType = 2075,
			AuditActivateSessionEventType_ClientSoftwareCertificates = 2076,
			AuditActivateSessionEventType_UserIdentityToken = 2077,
			AuditCancelEventType = 2078,
			AuditCancelEventType_RequestHandle = 2079,
			AuditCertificateEventType = 2080,
			AuditCertificateEventType_Certificate = 2081,
			AuditCertificateDataMismatchEventType = 2082,
			AuditCertificateDataMismatchEventType_InvalidHostname = 2083,
			AuditCertificateDataMismatchEventType_InvalidUri = 2084,
			AuditCertificateExpiredEventType = 2085,
			AuditCertificateInvalidEventType = 2086,
			AuditCertificateUntrustedEventType = 2087,
			AuditCertificateRevokedEventType = 2088,
			AuditCertificateMismatchEventType = 2089,
			AuditNodeManagementEventType = 2090,
			AuditAddNodesEventType = 2091,
			AuditAddNodesEventType_NodesToAdd = 2092,
			AuditDeleteNodesEventType = 2093,
			AuditDeleteNodesEventType_NodesToDelete = 2094,
			AuditAddReferencesEventType = 2095,
			AuditAddReferencesEventType_ReferencesToAdd = 2096,
			AuditDeleteReferencesEventType = 2097,
			AuditDeleteReferencesEventType_ReferencesToDelete = 2098,
			AuditUpdateEventType = 2099,
			AuditWriteUpdateEventType = 2100,
			AuditWriteUpdateEventType_IndexRange = 2101,
			AuditWriteUpdateEventType_OldValue = 2102,
			AuditWriteUpdateEventType_NewValue = 2103,
			AuditHistoryUpdateEventType = 2104,
			AuditUpdateMethodEventType = 2127,
			AuditUpdateMethodEventType_MethodId = 2128,
			AuditUpdateMethodEventType_InputArguments = 2129,
			SystemEventType = 2130,
			DeviceFailureEventType = 2131,
			BaseModelChangeEventType = 2132,
			GeneralModelChangeEventType = 2133,
			GeneralModelChangeEventType_Changes = 2134,
			ServerVendorCapabilityType = 2137,
			ServerStatusType = 2138,
			ServerStatusType_StartTime = 2139,
			ServerStatusType_CurrentTime = 2140,
			ServerStatusType_State = 2141,
			ServerStatusType_BuildInfo = 2142,
			ServerDiagnosticsSummaryType = 2150,
			ServerDiagnosticsSummaryType_ServerViewCount = 2151,
			ServerDiagnosticsSummaryType_CurrentSessionCount = 2152,
			ServerDiagnosticsSummaryType_CumulatedSessionCount = 2153,
			ServerDiagnosticsSummaryType_SecurityRejectedSessionCount = 2154,
			ServerDiagnosticsSummaryType_RejectedSessionCount = 2155,
			ServerDiagnosticsSummaryType_SessionTimeoutCount = 2156,
			ServerDiagnosticsSummaryType_SessionAbortCount = 2157,
			ServerDiagnosticsSummaryType_PublishingIntervalCount = 2159,
			ServerDiagnosticsSummaryType_CurrentSubscriptionCount = 2160,
			ServerDiagnosticsSummaryType_CumulatedSubscriptionCount = 2161,
			ServerDiagnosticsSummaryType_SecurityRejectedRequestsCount = 2162,
			ServerDiagnosticsSummaryType_RejectedRequestsCount = 2163,
			SamplingIntervalDiagnosticsArrayType = 2164,
			SamplingIntervalDiagnosticsType = 2165,
			SamplingIntervalDiagnosticsType_SamplingInterval = 2166,
			SubscriptionDiagnosticsArrayType = 2171,
			SubscriptionDiagnosticsType = 2172,
			SubscriptionDiagnosticsType_SessionId = 2173,
			SubscriptionDiagnosticsType_SubscriptionId = 2174,
			SubscriptionDiagnosticsType_Priority = 2175,
			SubscriptionDiagnosticsType_PublishingInterval = 2176,
			SubscriptionDiagnosticsType_MaxKeepAliveCount = 2177,
			SubscriptionDiagnosticsType_MaxNotificationsPerPublish = 2179,
			SubscriptionDiagnosticsType_PublishingEnabled = 2180,
			SubscriptionDiagnosticsType_ModifyCount = 2181,
			SubscriptionDiagnosticsType_EnableCount = 2182,
			SubscriptionDiagnosticsType_DisableCount = 2183,
			SubscriptionDiagnosticsType_RepublishRequestCount = 2184,
			SubscriptionDiagnosticsType_RepublishMessageRequestCount = 2185,
			SubscriptionDiagnosticsType_RepublishMessageCount = 2186,
			SubscriptionDiagnosticsType_TransferRequestCount = 2187,
			SubscriptionDiagnosticsType_TransferredToAltClientCount = 2188,
			SubscriptionDiagnosticsType_TransferredToSameClientCount = 2189,
			SubscriptionDiagnosticsType_PublishRequestCount = 2190,
			SubscriptionDiagnosticsType_DataChangeNotificationsCount = 2191,
			SubscriptionDiagnosticsType_NotificationsCount = 2193,
			SessionDiagnosticsArrayType = 2196,
			SessionDiagnosticsVariableType = 2197,
			SessionDiagnosticsVariableType_SessionId = 2198,
			SessionDiagnosticsVariableType_SessionName = 2199,
			SessionDiagnosticsVariableType_ClientDescription = 2200,
			SessionDiagnosticsVariableType_ServerUri = 2201,
			SessionDiagnosticsVariableType_EndpointUrl = 2202,
			SessionDiagnosticsVariableType_LocaleIds = 2203,
			SessionDiagnosticsVariableType_ActualSessionTimeout = 2204,
			SessionDiagnosticsVariableType_ClientConnectionTime = 2205,
			SessionDiagnosticsVariableType_ClientLastContactTime = 2206,
			SessionDiagnosticsVariableType_CurrentSubscriptionsCount = 2207,
			SessionDiagnosticsVariableType_CurrentMonitoredItemsCount = 2208,
			SessionDiagnosticsVariableType_CurrentPublishRequestsInQueue = 2209,
			SessionDiagnosticsVariableType_ReadCount = 2217,
			SessionDiagnosticsVariableType_HistoryReadCount = 2218,
			SessionDiagnosticsVariableType_WriteCount = 2219,
			SessionDiagnosticsVariableType_HistoryUpdateCount = 2220,
			SessionDiagnosticsVariableType_CallCount = 2221,
			SessionDiagnosticsVariableType_CreateMonitoredItemsCount = 2222,
			SessionDiagnosticsVariableType_ModifyMonitoredItemsCount = 2223,
			SessionDiagnosticsVariableType_SetMonitoringModeCount = 2224,
			SessionDiagnosticsVariableType_SetTriggeringCount = 2225,
			SessionDiagnosticsVariableType_DeleteMonitoredItemsCount = 2226,
			SessionDiagnosticsVariableType_CreateSubscriptionCount = 2227,
			SessionDiagnosticsVariableType_ModifySubscriptionCount = 2228,
			SessionDiagnosticsVariableType_SetPublishingModeCount = 2229,
			SessionDiagnosticsVariableType_PublishCount = 2230,
			SessionDiagnosticsVariableType_RepublishCount = 2231,
			SessionDiagnosticsVariableType_TransferSubscriptionsCount = 2232,
			SessionDiagnosticsVariableType_DeleteSubscriptionsCount = 2233,
			SessionDiagnosticsVariableType_AddNodesCount = 2234,
			SessionDiagnosticsVariableType_AddReferencesCount = 2235,
			SessionDiagnosticsVariableType_DeleteNodesCount = 2236,
			SessionDiagnosticsVariableType_DeleteReferencesCount = 2237,
			SessionDiagnosticsVariableType_BrowseCount = 2238,
			SessionDiagnosticsVariableType_BrowseNextCount = 2239,
			SessionDiagnosticsVariableType_TranslateBrowsePathsToNodeIdsCount = 2240,
			SessionDiagnosticsVariableType_QueryFirstCount = 2241,
			SessionDiagnosticsVariableType_QueryNextCount = 2242,
			SessionSecurityDiagnosticsArrayType = 2243,
			SessionSecurityDiagnosticsType = 2244,
			SessionSecurityDiagnosticsType_SessionId = 2245,
			SessionSecurityDiagnosticsType_ClientUserIdOfSession = 2246,
			SessionSecurityDiagnosticsType_ClientUserIdHistory = 2247,
			SessionSecurityDiagnosticsType_AuthenticationMechanism = 2248,
			SessionSecurityDiagnosticsType_Encoding = 2249,
			SessionSecurityDiagnosticsType_TransportProtocol = 2250,
			SessionSecurityDiagnosticsType_SecurityMode = 2251,
			SessionSecurityDiagnosticsType_SecurityPolicyUri = 2252,
			Server = 2253,
			Server_ServerArray = 2254,
			Server_NamespaceArray = 2255,
			Server_ServerStatus = 2256,
			Server_ServerStatus_StartTime = 2257,
			Server_ServerStatus_CurrentTime = 2258,
			Server_ServerStatus_State = 2259,
			Server_ServerStatus_BuildInfo = 2260,
			Server_ServerStatus_BuildInfo_ProductName = 2261,
			Server_ServerStatus_BuildInfo_ProductUri = 2262,
			Server_ServerStatus_BuildInfo_ManufacturerName = 2263,
			Server_ServerStatus_BuildInfo_SoftwareVersion = 2264,
			Server_ServerStatus_BuildInfo_BuildNumber = 2265,
			Server_ServerStatus_BuildInfo_BuildDate = 2266,
			Server_ServiceLevel = 2267,
			Server_ServerCapabilities = 2268,
			Server_ServerCapabilities_ServerProfileArray = 2269,
			Server_ServerCapabilities_LocaleIdArray = 2271,
			Server_ServerCapabilities_MinSupportedSampleRate = 2272,
			Server_ServerDiagnostics = 2274,
			Server_ServerDiagnostics_ServerDiagnosticsSummary = 2275,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount = 2276,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount = 2277,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount = 2278,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount = 2279,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount = 2281,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount = 2282,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount = 2284,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount = 2285,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount = 2286,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount = 2287,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount = 2288,
			Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray = 2289,
			Server_ServerDiagnostics_SubscriptionDiagnosticsArray = 2290,
			Server_ServerDiagnostics_EnabledFlag = 2294,
			Server_VendorServerInfo = 2295,
			Server_ServerRedundancy = 2296,
			StateMachineType = 2299,
			StateType = 2307,
			StateType_StateNumber = 2308,
			InitialStateType = 2309,
			TransitionType = 2310,
			TransitionEventType = 2311,
			TransitionType_TransitionNumber = 2312,
			AuditUpdateStateEventType = 2315,
			HistoricalDataConfigurationType = 2318,
			HistoricalDataConfigurationType_Stepped = 2323,
			HistoricalDataConfigurationType_Definition = 2324,
			HistoricalDataConfigurationType_MaxTimeInterval = 2325,
			HistoricalDataConfigurationType_MinTimeInterval = 2326,
			HistoricalDataConfigurationType_ExceptionDeviation = 2327,
			HistoricalDataConfigurationType_ExceptionDeviationFormat = 2328,
			HistoryServerCapabilitiesType = 2330,
			HistoryServerCapabilitiesType_AccessHistoryDataCapability = 2331,
			HistoryServerCapabilitiesType_AccessHistoryEventsCapability = 2332,
			HistoryServerCapabilitiesType_InsertDataCapability = 2334,
			HistoryServerCapabilitiesType_ReplaceDataCapability = 2335,
			HistoryServerCapabilitiesType_UpdateDataCapability = 2336,
			HistoryServerCapabilitiesType_DeleteRawCapability = 2337,
			HistoryServerCapabilitiesType_DeleteAtTimeCapability = 2338,
			AggregateFunctionType = 2340,
			AggregateFunction_Interpolative = 2341,
			AggregateFunction_Average = 2342,
			AggregateFunction_TimeAverage = 2343,
			AggregateFunction_Total = 2344,
			AggregateFunction_Minimum = 2346,
			AggregateFunction_Maximum = 2347,
			AggregateFunction_MinimumActualTime = 2348,
			AggregateFunction_MaximumActualTime = 2349,
			AggregateFunction_Range = 2350,
			AggregateFunction_AnnotationCount = 2351,
			AggregateFunction_Count = 2352,
			AggregateFunction_NumberOfTransitions = 2355,
			AggregateFunction_Start = 2357,
			AggregateFunction_End = 2358,
			AggregateFunction_Delta = 2359,
			AggregateFunction_DurationGood = 2360,
			AggregateFunction_DurationBad = 2361,
			AggregateFunction_PercentGood = 2362,
			AggregateFunction_PercentBad = 2363,
			AggregateFunction_WorstQuality = 2364,
			DataItemType = 2365,
			DataItemType_Definition = 2366,
			DataItemType_ValuePrecision = 2367,
			AnalogItemType = 2368,
			AnalogItemType_EURange = 2369,
			AnalogItemType_InstrumentRange = 2370,
			AnalogItemType_EngineeringUnits = 2371,
			DiscreteItemType = 2372,
			TwoStateDiscreteType = 2373,
			TwoStateDiscreteType_FalseState = 2374,
			TwoStateDiscreteType_TrueState = 2375,
			MultiStateDiscreteType = 2376,
			MultiStateDiscreteType_EnumStrings = 2377,
			ProgramTransitionEventType = 2378,
			ProgramTransitionEventType_IntermediateResult = 2379,
			ProgramDiagnosticType = 2380,
			ProgramDiagnosticType_CreateSessionId = 2381,
			ProgramDiagnosticType_CreateClientName = 2382,
			ProgramDiagnosticType_InvocationCreationTime = 2383,
			ProgramDiagnosticType_LastTransitionTime = 2384,
			ProgramDiagnosticType_LastMethodCall = 2385,
			ProgramDiagnosticType_LastMethodSessionId = 2386,
			ProgramDiagnosticType_LastMethodInputArguments = 2387,
			ProgramDiagnosticType_LastMethodOutputArguments = 2388,
			ProgramDiagnosticType_LastMethodCallTime = 2389,
			ProgramDiagnosticType_LastMethodReturnStatus = 2390,
			ProgramStateMachineType = 2391,
			ProgramStateMachineType_Creatable = 2392,
			ProgramStateMachineType_Deletable = 2393,
			ProgramStateMachineType_AutoDelete = 2394,
			ProgramStateMachineType_RecycleCount = 2395,
			ProgramStateMachineType_InstanceCount = 2396,
			ProgramStateMachineType_MaxInstanceCount = 2397,
			ProgramStateMachineType_MaxRecycleCount = 2398,
			ProgramStateMachineType_ProgramDiagnostics = 2399,
			ProgramStateMachineType_Ready = 2400,
			ProgramStateMachineType_Ready_StateNumber = 2401,
			ProgramStateMachineType_Running = 2402,
			ProgramStateMachineType_Running_StateNumber = 2403,
			ProgramStateMachineType_Suspended = 2404,
			ProgramStateMachineType_Suspended_StateNumber = 2405,
			ProgramStateMachineType_Halted = 2406,
			ProgramStateMachineType_Halted_StateNumber = 2407,
			ProgramStateMachineType_HaltedToReady = 2408,
			ProgramStateMachineType_HaltedToReady_TransitionNumber = 2409,
			ProgramStateMachineType_ReadyToRunning = 2410,
			ProgramStateMachineType_ReadyToRunning_TransitionNumber = 2411,
			ProgramStateMachineType_RunningToHalted = 2412,
			ProgramStateMachineType_RunningToHalted_TransitionNumber = 2413,
			ProgramStateMachineType_RunningToReady = 2414,
			ProgramStateMachineType_RunningToReady_TransitionNumber = 2415,
			ProgramStateMachineType_RunningToSuspended = 2416,
			ProgramStateMachineType_RunningToSuspended_TransitionNumber = 2417,
			ProgramStateMachineType_SuspendedToRunning = 2418,
			ProgramStateMachineType_SuspendedToRunning_TransitionNumber = 2419,
			ProgramStateMachineType_SuspendedToHalted = 2420,
			ProgramStateMachineType_SuspendedToHalted_TransitionNumber = 2421,
			ProgramStateMachineType_SuspendedToReady = 2422,
			ProgramStateMachineType_SuspendedToReady_TransitionNumber = 2423,
			ProgramStateMachineType_ReadyToHalted = 2424,
			ProgramStateMachineType_ReadyToHalted_TransitionNumber = 2425,
			ProgramStateMachineType_Start = 2426,
			ProgramStateMachineType_Suspend = 2427,
			ProgramStateMachineType_Resume = 2428,
			ProgramStateMachineType_Halt = 2429,
			ProgramStateMachineType_Reset = 2430,
			SessionDiagnosticsVariableType_RegisterNodesCount = 2730,
			SessionDiagnosticsVariableType_UnregisterNodesCount = 2731,
			ServerCapabilitiesType_MaxBrowseContinuationPoints = 2732,
			ServerCapabilitiesType_MaxQueryContinuationPoints = 2733,
			ServerCapabilitiesType_MaxHistoryContinuationPoints = 2734,
			Server_ServerCapabilities_MaxBrowseContinuationPoints = 2735,
			Server_ServerCapabilities_MaxQueryContinuationPoints = 2736,
			Server_ServerCapabilities_MaxHistoryContinuationPoints = 2737,
			SemanticChangeEventType = 2738,
			SemanticChangeEventType_Changes = 2739,
			ServerType_Auditing = 2742,
			ServerDiagnosticsType_SessionsDiagnosticsSummary = 2744,
			AuditChannelEventType_SecureChannelId = 2745,
			AuditOpenSecureChannelEventType_ClientCertificateThumbprint = 2746,
			AuditCreateSessionEventType_ClientCertificateThumbprint = 2747,
			AuditUrlMismatchEventType = 2748,
			AuditUrlMismatchEventType_EndpointUrl = 2749,
			AuditWriteUpdateEventType_AttributeId = 2750,
			AuditHistoryUpdateEventType_ParameterDataTypeId = 2751,
			ServerStatusType_SecondsTillShutdown = 2752,
			ServerStatusType_ShutdownReason = 2753,
			ServerCapabilitiesType_AggregateFunctions = 2754,
			StateVariableType = 2755,
			StateVariableType_Id = 2756,
			StateVariableType_Name = 2757,
			StateVariableType_Number = 2758,
			StateVariableType_EffectiveDisplayName = 2759,
			FiniteStateVariableType = 2760,
			FiniteStateVariableType_Id = 2761,
			TransitionVariableType = 2762,
			TransitionVariableType_Id = 2763,
			TransitionVariableType_Name = 2764,
			TransitionVariableType_Number = 2765,
			TransitionVariableType_TransitionTime = 2766,
			FiniteTransitionVariableType = 2767,
			FiniteTransitionVariableType_Id = 2768,
			StateMachineType_CurrentState = 2769,
			StateMachineType_LastTransition = 2770,
			FiniteStateMachineType = 2771,
			FiniteStateMachineType_CurrentState = 2772,
			FiniteStateMachineType_LastTransition = 2773,
			TransitionEventType_Transition = 2774,
			TransitionEventType_FromState = 2775,
			TransitionEventType_ToState = 2776,
			AuditUpdateStateEventType_OldStateId = 2777,
			AuditUpdateStateEventType_NewStateId = 2778,
			ConditionType = 2782,
			RefreshStartEventType = 2787,
			RefreshEndEventType = 2788,
			RefreshRequiredEventType = 2789,
			AuditConditionEventType = 2790,
			AuditConditionEnableEventType = 2803,
			AuditConditionCommentEventType = 2829,
			DialogConditionType = 2830,
			DialogConditionType_Prompt = 2831,
			AcknowledgeableConditionType = 2881,
			AlarmConditionType = 2915,
			ShelvedStateMachineType = 2929,
			ShelvedStateMachineType_Unshelved = 2930,
			ShelvedStateMachineType_TimedShelved = 2932,
			ShelvedStateMachineType_OneShotShelved = 2933,
			ShelvedStateMachineType_UnshelvedToTimedShelved = 2935,
			ShelvedStateMachineType_UnshelvedToOneShotShelved = 2936,
			ShelvedStateMachineType_TimedShelvedToUnshelved = 2940,
			ShelvedStateMachineType_TimedShelvedToOneShotShelved = 2942,
			ShelvedStateMachineType_OneShotShelvedToUnshelved = 2943,
			ShelvedStateMachineType_OneShotShelvedToTimedShelved = 2945,
			ShelvedStateMachineType_Unshelve = 2947,
			ShelvedStateMachineType_OneShotShelve = 2948,
			ShelvedStateMachineType_TimedShelve = 2949,
			LimitAlarmType = 2955,
			ShelvedStateMachineType_TimedShelve_InputArguments = 2991,
			Server_ServerStatus_SecondsTillShutdown = 2992,
			Server_ServerStatus_ShutdownReason = 2993,
			Server_Auditing = 2994,
			Server_ServerCapabilities_ModellingRules = 2996,
			Server_ServerCapabilities_AggregateFunctions = 2997,
			SubscriptionDiagnosticsType_EventNotificationsCount = 2998,
			AuditHistoryEventUpdateEventType = 2999,
			AuditHistoryEventUpdateEventType_Filter = 3003,
			AuditHistoryValueUpdateEventType = 3006,
			AuditHistoryDeleteEventType = 3012,
			AuditHistoryRawModifyDeleteEventType = 3014,
			AuditHistoryRawModifyDeleteEventType_IsDeleteModified = 3015,
			AuditHistoryRawModifyDeleteEventType_StartTime = 3016,
			AuditHistoryRawModifyDeleteEventType_EndTime = 3017,
			AuditHistoryAtTimeDeleteEventType = 3019,
			AuditHistoryAtTimeDeleteEventType_ReqTimes = 3020,
			AuditHistoryAtTimeDeleteEventType_OldValues = 3021,
			AuditHistoryEventDeleteEventType = 3022,
			AuditHistoryEventDeleteEventType_EventIds = 3023,
			AuditHistoryEventDeleteEventType_OldValues = 3024,
			AuditHistoryEventUpdateEventType_UpdatedNode = 3025,
			AuditHistoryValueUpdateEventType_UpdatedNode = 3026,
			AuditHistoryDeleteEventType_UpdatedNode = 3027,
			AuditHistoryEventUpdateEventType_PerformInsertReplace = 3028,
			AuditHistoryEventUpdateEventType_NewValues = 3029,
			AuditHistoryEventUpdateEventType_OldValues = 3030,
			AuditHistoryValueUpdateEventType_PerformInsertReplace = 3031,
			AuditHistoryValueUpdateEventType_NewValues = 3032,
			AuditHistoryValueUpdateEventType_OldValues = 3033,
			AuditHistoryRawModifyDeleteEventType_OldValues = 3034,
			EventQueueOverflowEventType = 3035,
			EventTypesFolder = 3048,
			ServerCapabilitiesType_SoftwareCertificates = 3049,
			SessionDiagnosticsVariableType_MaxResponseMessageSize = 3050,
			BuildInfoType = 3051,
			BuildInfoType_ProductUri = 3052,
			BuildInfoType_ManufacturerName = 3053,
			BuildInfoType_ProductName = 3054,
			BuildInfoType_SoftwareVersion = 3055,
			BuildInfoType_BuildNumber = 3056,
			BuildInfoType_BuildDate = 3057,
			SessionSecurityDiagnosticsType_ClientCertificate = 3058,
			HistoricalDataConfigurationType_AggregateConfiguration = 3059,
			DefaultBinary = 3062,
			DefaultXml = 3063,
			AlwaysGeneratesEvent = 3065,
			Icon = 3067,
			NodeVersion = 3068,
			LocalTime = 3069,
			AllowNulls = 3070,
			EnumValues = 3071,
			InputArguments = 3072,
			OutputArguments = 3073,
			ServerType_ServerStatus_StartTime = 3074,
			ServerType_ServerStatus_CurrentTime = 3075,
			ServerType_ServerStatus_State = 3076,
			ServerType_ServerStatus_BuildInfo = 3077,
			ServerType_ServerStatus_BuildInfo_ProductUri = 3078,
			ServerType_ServerStatus_BuildInfo_ManufacturerName = 3079,
			ServerType_ServerStatus_BuildInfo_ProductName = 3080,
			ServerType_ServerStatus_BuildInfo_SoftwareVersion = 3081,
			ServerType_ServerStatus_BuildInfo_BuildNumber = 3082,
			ServerType_ServerStatus_BuildInfo_BuildDate = 3083,
			ServerType_ServerStatus_SecondsTillShutdown = 3084,
			ServerType_ServerStatus_ShutdownReason = 3085,
			ServerType_ServerCapabilities_ServerProfileArray = 3086,
			ServerType_ServerCapabilities_LocaleIdArray = 3087,
			ServerType_ServerCapabilities_MinSupportedSampleRate = 3088,
			ServerType_ServerCapabilities_MaxBrowseContinuationPoints = 3089,
			ServerType_ServerCapabilities_MaxQueryContinuationPoints = 3090,
			ServerType_ServerCapabilities_MaxHistoryContinuationPoints = 3091,
			ServerType_ServerCapabilities_SoftwareCertificates = 3092,
			ServerType_ServerCapabilities_ModellingRules = 3093,
			ServerType_ServerCapabilities_AggregateFunctions = 3094,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary = 3095,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount = 3096,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount = 3097,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount = 3098,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount = 3099,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount = 3100,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount = 3101,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount = 3102,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount = 3104,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount = 3105,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount = 3106,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount = 3107,
			ServerType_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount = 3108,
			ServerType_ServerDiagnostics_SamplingIntervalDiagnosticsArray = 3109,
			ServerType_ServerDiagnostics_SubscriptionDiagnosticsArray = 3110,
			ServerType_ServerDiagnostics_SessionsDiagnosticsSummary = 3111,
			ServerType_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray = 3112,
			ServerType_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray = 3113,
			ServerType_ServerDiagnostics_EnabledFlag = 3114,
			ServerType_ServerRedundancy_RedundancySupport = 3115,
			ServerDiagnosticsType_ServerDiagnosticsSummary_ServerViewCount = 3116,
			ServerDiagnosticsType_ServerDiagnosticsSummary_CurrentSessionCount = 3117,
			ServerDiagnosticsType_ServerDiagnosticsSummary_CumulatedSessionCount = 3118,
			ServerDiagnosticsType_ServerDiagnosticsSummary_SecurityRejectedSessionCount = 3119,
			ServerDiagnosticsType_ServerDiagnosticsSummary_RejectedSessionCount = 3120,
			ServerDiagnosticsType_ServerDiagnosticsSummary_SessionTimeoutCount = 3121,
			ServerDiagnosticsType_ServerDiagnosticsSummary_SessionAbortCount = 3122,
			ServerDiagnosticsType_ServerDiagnosticsSummary_PublishingIntervalCount = 3124,
			ServerDiagnosticsType_ServerDiagnosticsSummary_CurrentSubscriptionCount = 3125,
			ServerDiagnosticsType_ServerDiagnosticsSummary_CumulatedSubscriptionCount = 3126,
			ServerDiagnosticsType_ServerDiagnosticsSummary_SecurityRejectedRequestsCount = 3127,
			ServerDiagnosticsType_ServerDiagnosticsSummary_RejectedRequestsCount = 3128,
			ServerDiagnosticsType_SessionsDiagnosticsSummary_SessionDiagnosticsArray = 3129,
			ServerDiagnosticsType_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray = 3130,
			SessionDiagnosticsObjectType_SessionDiagnostics_SessionId = 3131,
			SessionDiagnosticsObjectType_SessionDiagnostics_SessionName = 3132,
			SessionDiagnosticsObjectType_SessionDiagnostics_ClientDescription = 3133,
			SessionDiagnosticsObjectType_SessionDiagnostics_ServerUri = 3134,
			SessionDiagnosticsObjectType_SessionDiagnostics_EndpointUrl = 3135,
			SessionDiagnosticsObjectType_SessionDiagnostics_LocaleIds = 3136,
			SessionDiagnosticsObjectType_SessionDiagnostics_ActualSessionTimeout = 3137,
			SessionDiagnosticsObjectType_SessionDiagnostics_MaxResponseMessageSize = 3138,
			SessionDiagnosticsObjectType_SessionDiagnostics_ClientConnectionTime = 3139,
			SessionDiagnosticsObjectType_SessionDiagnostics_ClientLastContactTime = 3140,
			SessionDiagnosticsObjectType_SessionDiagnostics_CurrentSubscriptionsCount = 3141,
			SessionDiagnosticsObjectType_SessionDiagnostics_CurrentMonitoredItemsCount = 3142,
			SessionDiagnosticsObjectType_SessionDiagnostics_CurrentPublishRequestsInQueue = 3143,
			SessionDiagnosticsObjectType_SessionDiagnostics_ReadCount = 3151,
			SessionDiagnosticsObjectType_SessionDiagnostics_HistoryReadCount = 3152,
			SessionDiagnosticsObjectType_SessionDiagnostics_WriteCount = 3153,
			SessionDiagnosticsObjectType_SessionDiagnostics_HistoryUpdateCount = 3154,
			SessionDiagnosticsObjectType_SessionDiagnostics_CallCount = 3155,
			SessionDiagnosticsObjectType_SessionDiagnostics_CreateMonitoredItemsCount = 3156,
			SessionDiagnosticsObjectType_SessionDiagnostics_ModifyMonitoredItemsCount = 3157,
			SessionDiagnosticsObjectType_SessionDiagnostics_SetMonitoringModeCount = 3158,
			SessionDiagnosticsObjectType_SessionDiagnostics_SetTriggeringCount = 3159,
			SessionDiagnosticsObjectType_SessionDiagnostics_DeleteMonitoredItemsCount = 3160,
			SessionDiagnosticsObjectType_SessionDiagnostics_CreateSubscriptionCount = 3161,
			SessionDiagnosticsObjectType_SessionDiagnostics_ModifySubscriptionCount = 3162,
			SessionDiagnosticsObjectType_SessionDiagnostics_SetPublishingModeCount = 3163,
			SessionDiagnosticsObjectType_SessionDiagnostics_PublishCount = 3164,
			SessionDiagnosticsObjectType_SessionDiagnostics_RepublishCount = 3165,
			SessionDiagnosticsObjectType_SessionDiagnostics_TransferSubscriptionsCount = 3166,
			SessionDiagnosticsObjectType_SessionDiagnostics_DeleteSubscriptionsCount = 3167,
			SessionDiagnosticsObjectType_SessionDiagnostics_AddNodesCount = 3168,
			SessionDiagnosticsObjectType_SessionDiagnostics_AddReferencesCount = 3169,
			SessionDiagnosticsObjectType_SessionDiagnostics_DeleteNodesCount = 3170,
			SessionDiagnosticsObjectType_SessionDiagnostics_DeleteReferencesCount = 3171,
			SessionDiagnosticsObjectType_SessionDiagnostics_BrowseCount = 3172,
			SessionDiagnosticsObjectType_SessionDiagnostics_BrowseNextCount = 3173,
			SessionDiagnosticsObjectType_SessionDiagnostics_TranslateBrowsePathsToNodeIdsCount = 3174,
			SessionDiagnosticsObjectType_SessionDiagnostics_QueryFirstCount = 3175,
			SessionDiagnosticsObjectType_SessionDiagnostics_QueryNextCount = 3176,
			SessionDiagnosticsObjectType_SessionDiagnostics_RegisterNodesCount = 3177,
			SessionDiagnosticsObjectType_SessionDiagnostics_UnregisterNodesCount = 3178,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_SessionId = 3179,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_ClientUserIdOfSession = 3180,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_ClientUserIdHistory = 3181,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_AuthenticationMechanism = 3182,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_Encoding = 3183,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_TransportProtocol = 3184,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_SecurityMode = 3185,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_SecurityPolicyUri = 3186,
			SessionDiagnosticsObjectType_SessionSecurityDiagnostics_ClientCertificate = 3187,
			TransparentRedundancyType_RedundancySupport = 3188,
			NonTransparentRedundancyType_RedundancySupport = 3189,
			BaseEventType_LocalTime = 3190,
			EventQueueOverflowEventType_EventId = 3191,
			EventQueueOverflowEventType_EventType = 3192,
			EventQueueOverflowEventType_SourceNode = 3193,
			EventQueueOverflowEventType_SourceName = 3194,
			EventQueueOverflowEventType_Time = 3195,
			EventQueueOverflowEventType_ReceiveTime = 3196,
			EventQueueOverflowEventType_LocalTime = 3197,
			EventQueueOverflowEventType_Message = 3198,
			EventQueueOverflowEventType_Severity = 3199,
			AuditEventType_EventId = 3200,
			AuditEventType_EventType = 3201,
			AuditEventType_SourceNode = 3202,
			AuditEventType_SourceName = 3203,
			AuditEventType_Time = 3204,
			AuditEventType_ReceiveTime = 3205,
			AuditEventType_LocalTime = 3206,
			AuditEventType_Message = 3207,
			AuditEventType_Severity = 3208,
			AuditSecurityEventType_EventId = 3209,
			AuditSecurityEventType_EventType = 3210,
			AuditSecurityEventType_SourceNode = 3211,
			AuditSecurityEventType_SourceName = 3212,
			AuditSecurityEventType_Time = 3213,
			AuditSecurityEventType_ReceiveTime = 3214,
			AuditSecurityEventType_LocalTime = 3215,
			AuditSecurityEventType_Message = 3216,
			AuditSecurityEventType_Severity = 3217,
			AuditSecurityEventType_ActionTimeStamp = 3218,
			AuditSecurityEventType_Status = 3219,
			AuditSecurityEventType_ServerId = 3220,
			AuditSecurityEventType_ClientAuditEntryId = 3221,
			AuditSecurityEventType_ClientUserId = 3222,
			AuditChannelEventType_EventId = 3223,
			AuditChannelEventType_EventType = 3224,
			AuditChannelEventType_SourceNode = 3225,
			AuditChannelEventType_SourceName = 3226,
			AuditChannelEventType_Time = 3227,
			AuditChannelEventType_ReceiveTime = 3228,
			AuditChannelEventType_LocalTime = 3229,
			AuditChannelEventType_Message = 3230,
			AuditChannelEventType_Severity = 3231,
			AuditChannelEventType_ActionTimeStamp = 3232,
			AuditChannelEventType_Status = 3233,
			AuditChannelEventType_ServerId = 3234,
			AuditChannelEventType_ClientAuditEntryId = 3235,
			AuditChannelEventType_ClientUserId = 3236,
			AuditOpenSecureChannelEventType_EventId = 3237,
			AuditOpenSecureChannelEventType_EventType = 3238,
			AuditOpenSecureChannelEventType_SourceNode = 3239,
			AuditOpenSecureChannelEventType_SourceName = 3240,
			AuditOpenSecureChannelEventType_Time = 3241,
			AuditOpenSecureChannelEventType_ReceiveTime = 3242,
			AuditOpenSecureChannelEventType_LocalTime = 3243,
			AuditOpenSecureChannelEventType_Message = 3244,
			AuditOpenSecureChannelEventType_Severity = 3245,
			AuditOpenSecureChannelEventType_ActionTimeStamp = 3246,
			AuditOpenSecureChannelEventType_Status = 3247,
			AuditOpenSecureChannelEventType_ServerId = 3248,
			AuditOpenSecureChannelEventType_ClientAuditEntryId = 3249,
			AuditOpenSecureChannelEventType_ClientUserId = 3250,
			AuditOpenSecureChannelEventType_SecureChannelId = 3251,
			AuditSessionEventType_EventId = 3252,
			AuditSessionEventType_EventType = 3253,
			AuditSessionEventType_SourceNode = 3254,
			AuditSessionEventType_SourceName = 3255,
			AuditSessionEventType_Time = 3256,
			AuditSessionEventType_ReceiveTime = 3257,
			AuditSessionEventType_LocalTime = 3258,
			AuditSessionEventType_Message = 3259,
			AuditSessionEventType_Severity = 3260,
			AuditSessionEventType_ActionTimeStamp = 3261,
			AuditSessionEventType_Status = 3262,
			AuditSessionEventType_ServerId = 3263,
			AuditSessionEventType_ClientAuditEntryId = 3264,
			AuditSessionEventType_ClientUserId = 3265,
			AuditCreateSessionEventType_EventId = 3266,
			AuditCreateSessionEventType_EventType = 3267,
			AuditCreateSessionEventType_SourceNode = 3268,
			AuditCreateSessionEventType_SourceName = 3269,
			AuditCreateSessionEventType_Time = 3270,
			AuditCreateSessionEventType_ReceiveTime = 3271,
			AuditCreateSessionEventType_LocalTime = 3272,
			AuditCreateSessionEventType_Message = 3273,
			AuditCreateSessionEventType_Severity = 3274,
			AuditCreateSessionEventType_ActionTimeStamp = 3275,
			AuditCreateSessionEventType_Status = 3276,
			AuditCreateSessionEventType_ServerId = 3277,
			AuditCreateSessionEventType_ClientAuditEntryId = 3278,
			AuditCreateSessionEventType_ClientUserId = 3279,
			AuditCreateSessionEventType_SessionId = 3280,
			AuditUrlMismatchEventType_EventId = 3281,
			AuditUrlMismatchEventType_EventType = 3282,
			AuditUrlMismatchEventType_SourceNode = 3283,
			AuditUrlMismatchEventType_SourceName = 3284,
			AuditUrlMismatchEventType_Time = 3285,
			AuditUrlMismatchEventType_ReceiveTime = 3286,
			AuditUrlMismatchEventType_LocalTime = 3287,
			AuditUrlMismatchEventType_Message = 3288,
			AuditUrlMismatchEventType_Severity = 3289,
			AuditUrlMismatchEventType_ActionTimeStamp = 3290,
			AuditUrlMismatchEventType_Status = 3291,
			AuditUrlMismatchEventType_ServerId = 3292,
			AuditUrlMismatchEventType_ClientAuditEntryId = 3293,
			AuditUrlMismatchEventType_ClientUserId = 3294,
			AuditUrlMismatchEventType_SessionId = 3295,
			AuditUrlMismatchEventType_SecureChannelId = 3296,
			AuditUrlMismatchEventType_ClientCertificate = 3297,
			AuditUrlMismatchEventType_ClientCertificateThumbprint = 3298,
			AuditUrlMismatchEventType_RevisedSessionTimeout = 3299,
			AuditActivateSessionEventType_EventId = 3300,
			AuditActivateSessionEventType_EventType = 3301,
			AuditActivateSessionEventType_SourceNode = 3302,
			AuditActivateSessionEventType_SourceName = 3303,
			AuditActivateSessionEventType_Time = 3304,
			AuditActivateSessionEventType_ReceiveTime = 3305,
			AuditActivateSessionEventType_LocalTime = 3306,
			AuditActivateSessionEventType_Message = 3307,
			AuditActivateSessionEventType_Severity = 3308,
			AuditActivateSessionEventType_ActionTimeStamp = 3309,
			AuditActivateSessionEventType_Status = 3310,
			AuditActivateSessionEventType_ServerId = 3311,
			AuditActivateSessionEventType_ClientAuditEntryId = 3312,
			AuditActivateSessionEventType_ClientUserId = 3313,
			AuditActivateSessionEventType_SessionId = 3314,
			AuditCancelEventType_EventId = 3315,
			AuditCancelEventType_EventType = 3316,
			AuditCancelEventType_SourceNode = 3317,
			AuditCancelEventType_SourceName = 3318,
			AuditCancelEventType_Time = 3319,
			AuditCancelEventType_ReceiveTime = 3320,
			AuditCancelEventType_LocalTime = 3321,
			AuditCancelEventType_Message = 3322,
			AuditCancelEventType_Severity = 3323,
			AuditCancelEventType_ActionTimeStamp = 3324,
			AuditCancelEventType_Status = 3325,
			AuditCancelEventType_ServerId = 3326,
			AuditCancelEventType_ClientAuditEntryId = 3327,
			AuditCancelEventType_ClientUserId = 3328,
			AuditCancelEventType_SessionId = 3329,
			AuditCertificateEventType_EventId = 3330,
			AuditCertificateEventType_EventType = 3331,
			AuditCertificateEventType_SourceNode = 3332,
			AuditCertificateEventType_SourceName = 3333,
			AuditCertificateEventType_Time = 3334,
			AuditCertificateEventType_ReceiveTime = 3335,
			AuditCertificateEventType_LocalTime = 3336,
			AuditCertificateEventType_Message = 3337,
			AuditCertificateEventType_Severity = 3338,
			AuditCertificateEventType_ActionTimeStamp = 3339,
			AuditCertificateEventType_Status = 3340,
			AuditCertificateEventType_ServerId = 3341,
			AuditCertificateEventType_ClientAuditEntryId = 3342,
			AuditCertificateEventType_ClientUserId = 3343,
			AuditCertificateDataMismatchEventType_EventId = 3344,
			AuditCertificateDataMismatchEventType_EventType = 3345,
			AuditCertificateDataMismatchEventType_SourceNode = 3346,
			AuditCertificateDataMismatchEventType_SourceName = 3347,
			AuditCertificateDataMismatchEventType_Time = 3348,
			AuditCertificateDataMismatchEventType_ReceiveTime = 3349,
			AuditCertificateDataMismatchEventType_LocalTime = 3350,
			AuditCertificateDataMismatchEventType_Message = 3351,
			AuditCertificateDataMismatchEventType_Severity = 3352,
			AuditCertificateDataMismatchEventType_ActionTimeStamp = 3353,
			AuditCertificateDataMismatchEventType_Status = 3354,
			AuditCertificateDataMismatchEventType_ServerId = 3355,
			AuditCertificateDataMismatchEventType_ClientAuditEntryId = 3356,
			AuditCertificateDataMismatchEventType_ClientUserId = 3357,
			AuditCertificateDataMismatchEventType_Certificate = 3358,
			AuditCertificateExpiredEventType_EventId = 3359,
			AuditCertificateExpiredEventType_EventType = 3360,
			AuditCertificateExpiredEventType_SourceNode = 3361,
			AuditCertificateExpiredEventType_SourceName = 3362,
			AuditCertificateExpiredEventType_Time = 3363,
			AuditCertificateExpiredEventType_ReceiveTime = 3364,
			AuditCertificateExpiredEventType_LocalTime = 3365,
			AuditCertificateExpiredEventType_Message = 3366,
			AuditCertificateExpiredEventType_Severity = 3367,
			AuditCertificateExpiredEventType_ActionTimeStamp = 3368,
			AuditCertificateExpiredEventType_Status = 3369,
			AuditCertificateExpiredEventType_ServerId = 3370,
			AuditCertificateExpiredEventType_ClientAuditEntryId = 3371,
			AuditCertificateExpiredEventType_ClientUserId = 3372,
			AuditCertificateExpiredEventType_Certificate = 3373,
			AuditCertificateInvalidEventType_EventId = 3374,
			AuditCertificateInvalidEventType_EventType = 3375,
			AuditCertificateInvalidEventType_SourceNode = 3376,
			AuditCertificateInvalidEventType_SourceName = 3377,
			AuditCertificateInvalidEventType_Time = 3378,
			AuditCertificateInvalidEventType_ReceiveTime = 3379,
			AuditCertificateInvalidEventType_LocalTime = 3380,
			AuditCertificateInvalidEventType_Message = 3381,
			AuditCertificateInvalidEventType_Severity = 3382,
			AuditCertificateInvalidEventType_ActionTimeStamp = 3383,
			AuditCertificateInvalidEventType_Status = 3384,
			AuditCertificateInvalidEventType_ServerId = 3385,
			AuditCertificateInvalidEventType_ClientAuditEntryId = 3386,
			AuditCertificateInvalidEventType_ClientUserId = 3387,
			AuditCertificateInvalidEventType_Certificate = 3388,
			AuditCertificateUntrustedEventType_EventId = 3389,
			AuditCertificateUntrustedEventType_EventType = 3390,
			AuditCertificateUntrustedEventType_SourceNode = 3391,
			AuditCertificateUntrustedEventType_SourceName = 3392,
			AuditCertificateUntrustedEventType_Time = 3393,
			AuditCertificateUntrustedEventType_ReceiveTime = 3394,
			AuditCertificateUntrustedEventType_LocalTime = 3395,
			AuditCertificateUntrustedEventType_Message = 3396,
			AuditCertificateUntrustedEventType_Severity = 3397,
			AuditCertificateUntrustedEventType_ActionTimeStamp = 3398,
			AuditCertificateUntrustedEventType_Status = 3399,
			AuditCertificateUntrustedEventType_ServerId = 3400,
			AuditCertificateUntrustedEventType_ClientAuditEntryId = 3401,
			AuditCertificateUntrustedEventType_ClientUserId = 3402,
			AuditCertificateUntrustedEventType_Certificate = 3403,
			AuditCertificateRevokedEventType_EventId = 3404,
			AuditCertificateRevokedEventType_EventType = 3405,
			AuditCertificateRevokedEventType_SourceNode = 3406,
			AuditCertificateRevokedEventType_SourceName = 3407,
			AuditCertificateRevokedEventType_Time = 3408,
			AuditCertificateRevokedEventType_ReceiveTime = 3409,
			AuditCertificateRevokedEventType_LocalTime = 3410,
			AuditCertificateRevokedEventType_Message = 3411,
			AuditCertificateRevokedEventType_Severity = 3412,
			AuditCertificateRevokedEventType_ActionTimeStamp = 3413,
			AuditCertificateRevokedEventType_Status = 3414,
			AuditCertificateRevokedEventType_ServerId = 3415,
			AuditCertificateRevokedEventType_ClientAuditEntryId = 3416,
			AuditCertificateRevokedEventType_ClientUserId = 3417,
			AuditCertificateRevokedEventType_Certificate = 3418,
			AuditCertificateMismatchEventType_EventId = 3419,
			AuditCertificateMismatchEventType_EventType = 3420,
			AuditCertificateMismatchEventType_SourceNode = 3421,
			AuditCertificateMismatchEventType_SourceName = 3422,
			AuditCertificateMismatchEventType_Time = 3423,
			AuditCertificateMismatchEventType_ReceiveTime = 3424,
			AuditCertificateMismatchEventType_LocalTime = 3425,
			AuditCertificateMismatchEventType_Message = 3426,
			AuditCertificateMismatchEventType_Severity = 3427,
			AuditCertificateMismatchEventType_ActionTimeStamp = 3428,
			AuditCertificateMismatchEventType_Status = 3429,
			AuditCertificateMismatchEventType_ServerId = 3430,
			AuditCertificateMismatchEventType_ClientAuditEntryId = 3431,
			AuditCertificateMismatchEventType_ClientUserId = 3432,
			AuditCertificateMismatchEventType_Certificate = 3433,
			AuditNodeManagementEventType_EventId = 3434,
			AuditNodeManagementEventType_EventType = 3435,
			AuditNodeManagementEventType_SourceNode = 3436,
			AuditNodeManagementEventType_SourceName = 3437,
			AuditNodeManagementEventType_Time = 3438,
			AuditNodeManagementEventType_ReceiveTime = 3439,
			AuditNodeManagementEventType_LocalTime = 3440,
			AuditNodeManagementEventType_Message = 3441,
			AuditNodeManagementEventType_Severity = 3442,
			AuditNodeManagementEventType_ActionTimeStamp = 3443,
			AuditNodeManagementEventType_Status = 3444,
			AuditNodeManagementEventType_ServerId = 3445,
			AuditNodeManagementEventType_ClientAuditEntryId = 3446,
			AuditNodeManagementEventType_ClientUserId = 3447,
			AuditAddNodesEventType_EventId = 3448,
			AuditAddNodesEventType_EventType = 3449,
			AuditAddNodesEventType_SourceNode = 3450,
			AuditAddNodesEventType_SourceName = 3451,
			AuditAddNodesEventType_Time = 3452,
			AuditAddNodesEventType_ReceiveTime = 3453,
			AuditAddNodesEventType_LocalTime = 3454,
			AuditAddNodesEventType_Message = 3455,
			AuditAddNodesEventType_Severity = 3456,
			AuditAddNodesEventType_ActionTimeStamp = 3457,
			AuditAddNodesEventType_Status = 3458,
			AuditAddNodesEventType_ServerId = 3459,
			AuditAddNodesEventType_ClientAuditEntryId = 3460,
			AuditAddNodesEventType_ClientUserId = 3461,
			AuditDeleteNodesEventType_EventId = 3462,
			AuditDeleteNodesEventType_EventType = 3463,
			AuditDeleteNodesEventType_SourceNode = 3464,
			AuditDeleteNodesEventType_SourceName = 3465,
			AuditDeleteNodesEventType_Time = 3466,
			AuditDeleteNodesEventType_ReceiveTime = 3467,
			AuditDeleteNodesEventType_LocalTime = 3468,
			AuditDeleteNodesEventType_Message = 3469,
			AuditDeleteNodesEventType_Severity = 3470,
			AuditDeleteNodesEventType_ActionTimeStamp = 3471,
			AuditDeleteNodesEventType_Status = 3472,
			AuditDeleteNodesEventType_ServerId = 3473,
			AuditDeleteNodesEventType_ClientAuditEntryId = 3474,
			AuditDeleteNodesEventType_ClientUserId = 3475,
			AuditAddReferencesEventType_EventId = 3476,
			AuditAddReferencesEventType_EventType = 3477,
			AuditAddReferencesEventType_SourceNode = 3478,
			AuditAddReferencesEventType_SourceName = 3479,
			AuditAddReferencesEventType_Time = 3480,
			AuditAddReferencesEventType_ReceiveTime = 3481,
			AuditAddReferencesEventType_LocalTime = 3482,
			AuditAddReferencesEventType_Message = 3483,
			AuditAddReferencesEventType_Severity = 3484,
			AuditAddReferencesEventType_ActionTimeStamp = 3485,
			AuditAddReferencesEventType_Status = 3486,
			AuditAddReferencesEventType_ServerId = 3487,
			AuditAddReferencesEventType_ClientAuditEntryId = 3488,
			AuditAddReferencesEventType_ClientUserId = 3489,
			AuditDeleteReferencesEventType_EventId = 3490,
			AuditDeleteReferencesEventType_EventType = 3491,
			AuditDeleteReferencesEventType_SourceNode = 3492,
			AuditDeleteReferencesEventType_SourceName = 3493,
			AuditDeleteReferencesEventType_Time = 3494,
			AuditDeleteReferencesEventType_ReceiveTime = 3495,
			AuditDeleteReferencesEventType_LocalTime = 3496,
			AuditDeleteReferencesEventType_Message = 3497,
			AuditDeleteReferencesEventType_Severity = 3498,
			AuditDeleteReferencesEventType_ActionTimeStamp = 3499,
			AuditDeleteReferencesEventType_Status = 3500,
			AuditDeleteReferencesEventType_ServerId = 3501,
			AuditDeleteReferencesEventType_ClientAuditEntryId = 3502,
			AuditDeleteReferencesEventType_ClientUserId = 3503,
			AuditUpdateEventType_EventId = 3504,
			AuditUpdateEventType_EventType = 3505,
			AuditUpdateEventType_SourceNode = 3506,
			AuditUpdateEventType_SourceName = 3507,
			AuditUpdateEventType_Time = 3508,
			AuditUpdateEventType_ReceiveTime = 3509,
			AuditUpdateEventType_LocalTime = 3510,
			AuditUpdateEventType_Message = 3511,
			AuditUpdateEventType_Severity = 3512,
			AuditUpdateEventType_ActionTimeStamp = 3513,
			AuditUpdateEventType_Status = 3514,
			AuditUpdateEventType_ServerId = 3515,
			AuditUpdateEventType_ClientAuditEntryId = 3516,
			AuditUpdateEventType_ClientUserId = 3517,
			AuditWriteUpdateEventType_EventId = 3518,
			AuditWriteUpdateEventType_EventType = 3519,
			AuditWriteUpdateEventType_SourceNode = 3520,
			AuditWriteUpdateEventType_SourceName = 3521,
			AuditWriteUpdateEventType_Time = 3522,
			AuditWriteUpdateEventType_ReceiveTime = 3523,
			AuditWriteUpdateEventType_LocalTime = 3524,
			AuditWriteUpdateEventType_Message = 3525,
			AuditWriteUpdateEventType_Severity = 3526,
			AuditWriteUpdateEventType_ActionTimeStamp = 3527,
			AuditWriteUpdateEventType_Status = 3528,
			AuditWriteUpdateEventType_ServerId = 3529,
			AuditWriteUpdateEventType_ClientAuditEntryId = 3530,
			AuditWriteUpdateEventType_ClientUserId = 3531,
			AuditHistoryUpdateEventType_EventId = 3532,
			AuditHistoryUpdateEventType_EventType = 3533,
			AuditHistoryUpdateEventType_SourceNode = 3534,
			AuditHistoryUpdateEventType_SourceName = 3535,
			AuditHistoryUpdateEventType_Time = 3536,
			AuditHistoryUpdateEventType_ReceiveTime = 3537,
			AuditHistoryUpdateEventType_LocalTime = 3538,
			AuditHistoryUpdateEventType_Message = 3539,
			AuditHistoryUpdateEventType_Severity = 3540,
			AuditHistoryUpdateEventType_ActionTimeStamp = 3541,
			AuditHistoryUpdateEventType_Status = 3542,
			AuditHistoryUpdateEventType_ServerId = 3543,
			AuditHistoryUpdateEventType_ClientAuditEntryId = 3544,
			AuditHistoryUpdateEventType_ClientUserId = 3545,
			AuditHistoryEventUpdateEventType_EventId = 3546,
			AuditHistoryEventUpdateEventType_EventType = 3547,
			AuditHistoryEventUpdateEventType_SourceNode = 3548,
			AuditHistoryEventUpdateEventType_SourceName = 3549,
			AuditHistoryEventUpdateEventType_Time = 3550,
			AuditHistoryEventUpdateEventType_ReceiveTime = 3551,
			AuditHistoryEventUpdateEventType_LocalTime = 3552,
			AuditHistoryEventUpdateEventType_Message = 3553,
			AuditHistoryEventUpdateEventType_Severity = 3554,
			AuditHistoryEventUpdateEventType_ActionTimeStamp = 3555,
			AuditHistoryEventUpdateEventType_Status = 3556,
			AuditHistoryEventUpdateEventType_ServerId = 3557,
			AuditHistoryEventUpdateEventType_ClientAuditEntryId = 3558,
			AuditHistoryEventUpdateEventType_ClientUserId = 3559,
			AuditHistoryEventUpdateEventType_ParameterDataTypeId = 3560,
			AuditHistoryValueUpdateEventType_EventId = 3561,
			AuditHistoryValueUpdateEventType_EventType = 3562,
			AuditHistoryValueUpdateEventType_SourceNode = 3563,
			AuditHistoryValueUpdateEventType_SourceName = 3564,
			AuditHistoryValueUpdateEventType_Time = 3565,
			AuditHistoryValueUpdateEventType_ReceiveTime = 3566,
			AuditHistoryValueUpdateEventType_LocalTime = 3567,
			AuditHistoryValueUpdateEventType_Message = 3568,
			AuditHistoryValueUpdateEventType_Severity = 3569,
			AuditHistoryValueUpdateEventType_ActionTimeStamp = 3570,
			AuditHistoryValueUpdateEventType_Status = 3571,
			AuditHistoryValueUpdateEventType_ServerId = 3572,
			AuditHistoryValueUpdateEventType_ClientAuditEntryId = 3573,
			AuditHistoryValueUpdateEventType_ClientUserId = 3574,
			AuditHistoryValueUpdateEventType_ParameterDataTypeId = 3575,
			AuditHistoryDeleteEventType_EventId = 3576,
			AuditHistoryDeleteEventType_EventType = 3577,
			AuditHistoryDeleteEventType_SourceNode = 3578,
			AuditHistoryDeleteEventType_SourceName = 3579,
			AuditHistoryDeleteEventType_Time = 3580,
			AuditHistoryDeleteEventType_ReceiveTime = 3581,
			AuditHistoryDeleteEventType_LocalTime = 3582,
			AuditHistoryDeleteEventType_Message = 3583,
			AuditHistoryDeleteEventType_Severity = 3584,
			AuditHistoryDeleteEventType_ActionTimeStamp = 3585,
			AuditHistoryDeleteEventType_Status = 3586,
			AuditHistoryDeleteEventType_ServerId = 3587,
			AuditHistoryDeleteEventType_ClientAuditEntryId = 3588,
			AuditHistoryDeleteEventType_ClientUserId = 3589,
			AuditHistoryDeleteEventType_ParameterDataTypeId = 3590,
			AuditHistoryRawModifyDeleteEventType_EventId = 3591,
			AuditHistoryRawModifyDeleteEventType_EventType = 3592,
			AuditHistoryRawModifyDeleteEventType_SourceNode = 3593,
			AuditHistoryRawModifyDeleteEventType_SourceName = 3594,
			AuditHistoryRawModifyDeleteEventType_Time = 3595,
			AuditHistoryRawModifyDeleteEventType_ReceiveTime = 3596,
			AuditHistoryRawModifyDeleteEventType_LocalTime = 3597,
			AuditHistoryRawModifyDeleteEventType_Message = 3598,
			AuditHistoryRawModifyDeleteEventType_Severity = 3599,
			AuditHistoryRawModifyDeleteEventType_ActionTimeStamp = 3600,
			AuditHistoryRawModifyDeleteEventType_Status = 3601,
			AuditHistoryRawModifyDeleteEventType_ServerId = 3602,
			AuditHistoryRawModifyDeleteEventType_ClientAuditEntryId = 3603,
			AuditHistoryRawModifyDeleteEventType_ClientUserId = 3604,
			AuditHistoryRawModifyDeleteEventType_ParameterDataTypeId = 3605,
			AuditHistoryRawModifyDeleteEventType_UpdatedNode = 3606,
			AuditHistoryAtTimeDeleteEventType_EventId = 3607,
			AuditHistoryAtTimeDeleteEventType_EventType = 3608,
			AuditHistoryAtTimeDeleteEventType_SourceNode = 3609,
			AuditHistoryAtTimeDeleteEventType_SourceName = 3610,
			AuditHistoryAtTimeDeleteEventType_Time = 3611,
			AuditHistoryAtTimeDeleteEventType_ReceiveTime = 3612,
			AuditHistoryAtTimeDeleteEventType_LocalTime = 3613,
			AuditHistoryAtTimeDeleteEventType_Message = 3614,
			AuditHistoryAtTimeDeleteEventType_Severity = 3615,
			AuditHistoryAtTimeDeleteEventType_ActionTimeStamp = 3616,
			AuditHistoryAtTimeDeleteEventType_Status = 3617,
			AuditHistoryAtTimeDeleteEventType_ServerId = 3618,
			AuditHistoryAtTimeDeleteEventType_ClientAuditEntryId = 3619,
			AuditHistoryAtTimeDeleteEventType_ClientUserId = 3620,
			AuditHistoryAtTimeDeleteEventType_ParameterDataTypeId = 3621,
			AuditHistoryAtTimeDeleteEventType_UpdatedNode = 3622,
			AuditHistoryEventDeleteEventType_EventId = 3623,
			AuditHistoryEventDeleteEventType_EventType = 3624,
			AuditHistoryEventDeleteEventType_SourceNode = 3625,
			AuditHistoryEventDeleteEventType_SourceName = 3626,
			AuditHistoryEventDeleteEventType_Time = 3627,
			AuditHistoryEventDeleteEventType_ReceiveTime = 3628,
			AuditHistoryEventDeleteEventType_LocalTime = 3629,
			AuditHistoryEventDeleteEventType_Message = 3630,
			AuditHistoryEventDeleteEventType_Severity = 3631,
			AuditHistoryEventDeleteEventType_ActionTimeStamp = 3632,
			AuditHistoryEventDeleteEventType_Status = 3633,
			AuditHistoryEventDeleteEventType_ServerId = 3634,
			AuditHistoryEventDeleteEventType_ClientAuditEntryId = 3635,
			AuditHistoryEventDeleteEventType_ClientUserId = 3636,
			AuditHistoryEventDeleteEventType_ParameterDataTypeId = 3637,
			AuditHistoryEventDeleteEventType_UpdatedNode = 3638,
			AuditUpdateMethodEventType_EventId = 3639,
			AuditUpdateMethodEventType_EventType = 3640,
			AuditUpdateMethodEventType_SourceNode = 3641,
			AuditUpdateMethodEventType_SourceName = 3642,
			AuditUpdateMethodEventType_Time = 3643,
			AuditUpdateMethodEventType_ReceiveTime = 3644,
			AuditUpdateMethodEventType_LocalTime = 3645,
			AuditUpdateMethodEventType_Message = 3646,
			AuditUpdateMethodEventType_Severity = 3647,
			AuditUpdateMethodEventType_ActionTimeStamp = 3648,
			AuditUpdateMethodEventType_Status = 3649,
			AuditUpdateMethodEventType_ServerId = 3650,
			AuditUpdateMethodEventType_ClientAuditEntryId = 3651,
			AuditUpdateMethodEventType_ClientUserId = 3652,
			SystemEventType_EventId = 3653,
			SystemEventType_EventType = 3654,
			SystemEventType_SourceNode = 3655,
			SystemEventType_SourceName = 3656,
			SystemEventType_Time = 3657,
			SystemEventType_ReceiveTime = 3658,
			SystemEventType_LocalTime = 3659,
			SystemEventType_Message = 3660,
			SystemEventType_Severity = 3661,
			DeviceFailureEventType_EventId = 3662,
			DeviceFailureEventType_EventType = 3663,
			DeviceFailureEventType_SourceNode = 3664,
			DeviceFailureEventType_SourceName = 3665,
			DeviceFailureEventType_Time = 3666,
			DeviceFailureEventType_ReceiveTime = 3667,
			DeviceFailureEventType_LocalTime = 3668,
			DeviceFailureEventType_Message = 3669,
			DeviceFailureEventType_Severity = 3670,
			BaseModelChangeEventType_EventId = 3671,
			BaseModelChangeEventType_EventType = 3672,
			BaseModelChangeEventType_SourceNode = 3673,
			BaseModelChangeEventType_SourceName = 3674,
			BaseModelChangeEventType_Time = 3675,
			BaseModelChangeEventType_ReceiveTime = 3676,
			BaseModelChangeEventType_LocalTime = 3677,
			BaseModelChangeEventType_Message = 3678,
			BaseModelChangeEventType_Severity = 3679,
			GeneralModelChangeEventType_EventId = 3680,
			GeneralModelChangeEventType_EventType = 3681,
			GeneralModelChangeEventType_SourceNode = 3682,
			GeneralModelChangeEventType_SourceName = 3683,
			GeneralModelChangeEventType_Time = 3684,
			GeneralModelChangeEventType_ReceiveTime = 3685,
			GeneralModelChangeEventType_LocalTime = 3686,
			GeneralModelChangeEventType_Message = 3687,
			GeneralModelChangeEventType_Severity = 3688,
			SemanticChangeEventType_EventId = 3689,
			SemanticChangeEventType_EventType = 3690,
			SemanticChangeEventType_SourceNode = 3691,
			SemanticChangeEventType_SourceName = 3692,
			SemanticChangeEventType_Time = 3693,
			SemanticChangeEventType_ReceiveTime = 3694,
			SemanticChangeEventType_LocalTime = 3695,
			SemanticChangeEventType_Message = 3696,
			SemanticChangeEventType_Severity = 3697,
			ServerStatusType_BuildInfo_ProductUri = 3698,
			ServerStatusType_BuildInfo_ManufacturerName = 3699,
			ServerStatusType_BuildInfo_ProductName = 3700,
			ServerStatusType_BuildInfo_SoftwareVersion = 3701,
			ServerStatusType_BuildInfo_BuildNumber = 3702,
			ServerStatusType_BuildInfo_BuildDate = 3703,
			Server_ServerCapabilities_SoftwareCertificates = 3704,
			Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount = 3705,
			Server_ServerDiagnostics_SessionsDiagnosticsSummary = 3706,
			Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray = 3707,
			Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray = 3708,
			Server_ServerRedundancy_RedundancySupport = 3709,
			FiniteStateVariableType_Name = 3714,
			FiniteStateVariableType_Number = 3715,
			FiniteStateVariableType_EffectiveDisplayName = 3716,
			FiniteTransitionVariableType_Name = 3717,
			FiniteTransitionVariableType_Number = 3718,
			FiniteTransitionVariableType_TransitionTime = 3719,
			StateMachineType_CurrentState_Id = 3720,
			StateMachineType_CurrentState_Name = 3721,
			StateMachineType_CurrentState_Number = 3722,
			StateMachineType_CurrentState_EffectiveDisplayName = 3723,
			StateMachineType_LastTransition_Id = 3724,
			StateMachineType_LastTransition_Name = 3725,
			StateMachineType_LastTransition_Number = 3726,
			StateMachineType_LastTransition_TransitionTime = 3727,
			FiniteStateMachineType_CurrentState_Id = 3728,
			FiniteStateMachineType_CurrentState_Name = 3729,
			FiniteStateMachineType_CurrentState_Number = 3730,
			FiniteStateMachineType_CurrentState_EffectiveDisplayName = 3731,
			FiniteStateMachineType_LastTransition_Id = 3732,
			FiniteStateMachineType_LastTransition_Name = 3733,
			FiniteStateMachineType_LastTransition_Number = 3734,
			FiniteStateMachineType_LastTransition_TransitionTime = 3735,
			InitialStateType_StateNumber = 3736,
			TransitionEventType_EventId = 3737,
			TransitionEventType_EventType = 3738,
			TransitionEventType_SourceNode = 3739,
			TransitionEventType_SourceName = 3740,
			TransitionEventType_Time = 3741,
			TransitionEventType_ReceiveTime = 3742,
			TransitionEventType_LocalTime = 3743,
			TransitionEventType_Message = 3744,
			TransitionEventType_Severity = 3745,
			TransitionEventType_FromState_Id = 3746,
			TransitionEventType_FromState_Name = 3747,
			TransitionEventType_FromState_Number = 3748,
			TransitionEventType_FromState_EffectiveDisplayName = 3749,
			TransitionEventType_ToState_Id = 3750,
			TransitionEventType_ToState_Name = 3751,
			TransitionEventType_ToState_Number = 3752,
			TransitionEventType_ToState_EffectiveDisplayName = 3753,
			TransitionEventType_Transition_Id = 3754,
			TransitionEventType_Transition_Name = 3755,
			TransitionEventType_Transition_Number = 3756,
			TransitionEventType_Transition_TransitionTime = 3757,
			AuditUpdateStateEventType_EventId = 3758,
			AuditUpdateStateEventType_EventType = 3759,
			AuditUpdateStateEventType_SourceNode = 3760,
			AuditUpdateStateEventType_SourceName = 3761,
			AuditUpdateStateEventType_Time = 3762,
			AuditUpdateStateEventType_ReceiveTime = 3763,
			AuditUpdateStateEventType_LocalTime = 3764,
			AuditUpdateStateEventType_Message = 3765,
			AuditUpdateStateEventType_Severity = 3766,
			AuditUpdateStateEventType_ActionTimeStamp = 3767,
			AuditUpdateStateEventType_Status = 3768,
			AuditUpdateStateEventType_ServerId = 3769,
			AuditUpdateStateEventType_ClientAuditEntryId = 3770,
			AuditUpdateStateEventType_ClientUserId = 3771,
			AuditUpdateStateEventType_MethodId = 3772,
			AuditUpdateStateEventType_InputArguments = 3773,
			AnalogItemType_Definition = 3774,
			AnalogItemType_ValuePrecision = 3775,
			DiscreteItemType_Definition = 3776,
			DiscreteItemType_ValuePrecision = 3777,
			TwoStateDiscreteType_Definition = 3778,
			TwoStateDiscreteType_ValuePrecision = 3779,
			MultiStateDiscreteType_Definition = 3780,
			MultiStateDiscreteType_ValuePrecision = 3781,
			ProgramTransitionEventType_EventId = 3782,
			ProgramTransitionEventType_EventType = 3783,
			ProgramTransitionEventType_SourceNode = 3784,
			ProgramTransitionEventType_SourceName = 3785,
			ProgramTransitionEventType_Time = 3786,
			ProgramTransitionEventType_ReceiveTime = 3787,
			ProgramTransitionEventType_LocalTime = 3788,
			ProgramTransitionEventType_Message = 3789,
			ProgramTransitionEventType_Severity = 3790,
			ProgramTransitionEventType_FromState = 3791,
			ProgramTransitionEventType_FromState_Id = 3792,
			ProgramTransitionEventType_FromState_Name = 3793,
			ProgramTransitionEventType_FromState_Number = 3794,
			ProgramTransitionEventType_FromState_EffectiveDisplayName = 3795,
			ProgramTransitionEventType_ToState = 3796,
			ProgramTransitionEventType_ToState_Id = 3797,
			ProgramTransitionEventType_ToState_Name = 3798,
			ProgramTransitionEventType_ToState_Number = 3799,
			ProgramTransitionEventType_ToState_EffectiveDisplayName = 3800,
			ProgramTransitionEventType_Transition = 3801,
			ProgramTransitionEventType_Transition_Id = 3802,
			ProgramTransitionEventType_Transition_Name = 3803,
			ProgramTransitionEventType_Transition_Number = 3804,
			ProgramTransitionEventType_Transition_TransitionTime = 3805,
			ProgramTransitionAuditEventType = 3806,
			ProgramTransitionAuditEventType_EventId = 3807,
			ProgramTransitionAuditEventType_EventType = 3808,
			ProgramTransitionAuditEventType_SourceNode = 3809,
			ProgramTransitionAuditEventType_SourceName = 3810,
			ProgramTransitionAuditEventType_Time = 3811,
			ProgramTransitionAuditEventType_ReceiveTime = 3812,
			ProgramTransitionAuditEventType_LocalTime = 3813,
			ProgramTransitionAuditEventType_Message = 3814,
			ProgramTransitionAuditEventType_Severity = 3815,
			ProgramTransitionAuditEventType_ActionTimeStamp = 3816,
			ProgramTransitionAuditEventType_Status = 3817,
			ProgramTransitionAuditEventType_ServerId = 3818,
			ProgramTransitionAuditEventType_ClientAuditEntryId = 3819,
			ProgramTransitionAuditEventType_ClientUserId = 3820,
			ProgramTransitionAuditEventType_MethodId = 3821,
			ProgramTransitionAuditEventType_InputArguments = 3822,
			ProgramTransitionAuditEventType_OldStateId = 3823,
			ProgramTransitionAuditEventType_NewStateId = 3824,
			ProgramTransitionAuditEventType_Transition = 3825,
			ProgramTransitionAuditEventType_Transition_Id = 3826,
			ProgramTransitionAuditEventType_Transition_Name = 3827,
			ProgramTransitionAuditEventType_Transition_Number = 3828,
			ProgramTransitionAuditEventType_Transition_TransitionTime = 3829,
			ProgramStateMachineType_CurrentState = 3830,
			ProgramStateMachineType_CurrentState_Id = 3831,
			ProgramStateMachineType_CurrentState_Name = 3832,
			ProgramStateMachineType_CurrentState_Number = 3833,
			ProgramStateMachineType_CurrentState_EffectiveDisplayName = 3834,
			ProgramStateMachineType_LastTransition = 3835,
			ProgramStateMachineType_LastTransition_Id = 3836,
			ProgramStateMachineType_LastTransition_Name = 3837,
			ProgramStateMachineType_LastTransition_Number = 3838,
			ProgramStateMachineType_LastTransition_TransitionTime = 3839,
			ProgramStateMachineType_ProgramDiagnostics_CreateSessionId = 3840,
			ProgramStateMachineType_ProgramDiagnostics_CreateClientName = 3841,
			ProgramStateMachineType_ProgramDiagnostics_InvocationCreationTime = 3842,
			ProgramStateMachineType_ProgramDiagnostics_LastTransitionTime = 3843,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodCall = 3844,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodSessionId = 3845,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodInputArguments = 3846,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodOutputArguments = 3847,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodCallTime = 3848,
			ProgramStateMachineType_ProgramDiagnostics_LastMethodReturnStatus = 3849,
			ProgramStateMachineType_FinalResultData = 3850,
			AddCommentMethodType = 3863,
			AddCommentMethodType_InputArguments = 3864,
			ConditionType_EventId = 3865,
			ConditionType_EventType = 3866,
			ConditionType_SourceNode = 3867,
			ConditionType_SourceName = 3868,
			ConditionType_Time = 3869,
			ConditionType_ReceiveTime = 3870,
			ConditionType_LocalTime = 3871,
			ConditionType_Message = 3872,
			ConditionType_Severity = 3873,
			ConditionType_Retain = 3874,
			ConditionType_ConditionRefresh = 3875,
			ConditionType_ConditionRefresh_InputArguments = 3876,
			RefreshStartEventType_EventId = 3969,
			RefreshStartEventType_EventType = 3970,
			RefreshStartEventType_SourceNode = 3971,
			RefreshStartEventType_SourceName = 3972,
			RefreshStartEventType_Time = 3973,
			RefreshStartEventType_ReceiveTime = 3974,
			RefreshStartEventType_LocalTime = 3975,
			RefreshStartEventType_Message = 3976,
			RefreshStartEventType_Severity = 3977,
			RefreshEndEventType_EventId = 3978,
			RefreshEndEventType_EventType = 3979,
			RefreshEndEventType_SourceNode = 3980,
			RefreshEndEventType_SourceName = 3981,
			RefreshEndEventType_Time = 3982,
			RefreshEndEventType_ReceiveTime = 3983,
			RefreshEndEventType_LocalTime = 3984,
			RefreshEndEventType_Message = 3985,
			RefreshEndEventType_Severity = 3986,
			RefreshRequiredEventType_EventId = 3987,
			RefreshRequiredEventType_EventType = 3988,
			RefreshRequiredEventType_SourceNode = 3989,
			RefreshRequiredEventType_SourceName = 3990,
			RefreshRequiredEventType_Time = 3991,
			RefreshRequiredEventType_ReceiveTime = 3992,
			RefreshRequiredEventType_LocalTime = 3993,
			RefreshRequiredEventType_Message = 3994,
			RefreshRequiredEventType_Severity = 3995,
			AuditConditionEventType_EventId = 3996,
			AuditConditionEventType_EventType = 3997,
			AuditConditionEventType_SourceNode = 3998,
			AuditConditionEventType_SourceName = 3999,
			AuditConditionEventType_Time = 4000,
			AuditConditionEventType_ReceiveTime = 4001,
			AuditConditionEventType_LocalTime = 4002,
			AuditConditionEventType_Message = 4003,
			AuditConditionEventType_Severity = 4004,
			AuditConditionEventType_ActionTimeStamp = 4005,
			AuditConditionEventType_Status = 4006,
			AuditConditionEventType_ServerId = 4007,
			AuditConditionEventType_ClientAuditEntryId = 4008,
			AuditConditionEventType_ClientUserId = 4009,
			AuditConditionEventType_MethodId = 4010,
			AuditConditionEventType_InputArguments = 4011,
			AuditConditionEnableEventType_EventId = 4106,
			AuditConditionEnableEventType_EventType = 4107,
			AuditConditionEnableEventType_SourceNode = 4108,
			AuditConditionEnableEventType_SourceName = 4109,
			AuditConditionEnableEventType_Time = 4110,
			AuditConditionEnableEventType_ReceiveTime = 4111,
			AuditConditionEnableEventType_LocalTime = 4112,
			AuditConditionEnableEventType_Message = 4113,
			AuditConditionEnableEventType_Severity = 4114,
			AuditConditionEnableEventType_ActionTimeStamp = 4115,
			AuditConditionEnableEventType_Status = 4116,
			AuditConditionEnableEventType_ServerId = 4117,
			AuditConditionEnableEventType_ClientAuditEntryId = 4118,
			AuditConditionEnableEventType_ClientUserId = 4119,
			AuditConditionEnableEventType_MethodId = 4120,
			AuditConditionEnableEventType_InputArguments = 4121,
			AuditConditionCommentEventType_EventId = 4170,
			AuditConditionCommentEventType_EventType = 4171,
			AuditConditionCommentEventType_SourceNode = 4172,
			AuditConditionCommentEventType_SourceName = 4173,
			AuditConditionCommentEventType_Time = 4174,
			AuditConditionCommentEventType_ReceiveTime = 4175,
			AuditConditionCommentEventType_LocalTime = 4176,
			AuditConditionCommentEventType_Message = 4177,
			AuditConditionCommentEventType_Severity = 4178,
			AuditConditionCommentEventType_ActionTimeStamp = 4179,
			AuditConditionCommentEventType_Status = 4180,
			AuditConditionCommentEventType_ServerId = 4181,
			AuditConditionCommentEventType_ClientAuditEntryId = 4182,
			AuditConditionCommentEventType_ClientUserId = 4183,
			AuditConditionCommentEventType_MethodId = 4184,
			AuditConditionCommentEventType_InputArguments = 4185,
			DialogConditionType_EventId = 4188,
			DialogConditionType_EventType = 4189,
			DialogConditionType_SourceNode = 4190,
			DialogConditionType_SourceName = 4191,
			DialogConditionType_Time = 4192,
			DialogConditionType_ReceiveTime = 4193,
			DialogConditionType_LocalTime = 4194,
			DialogConditionType_Message = 4195,
			DialogConditionType_Severity = 4196,
			DialogConditionType_Retain = 4197,
			DialogConditionType_ConditionRefresh = 4198,
			DialogConditionType_ConditionRefresh_InputArguments = 4199,
			AcknowledgeableConditionType_EventId = 5113,
			AcknowledgeableConditionType_EventType = 5114,
			AcknowledgeableConditionType_SourceNode = 5115,
			AcknowledgeableConditionType_SourceName = 5116,
			AcknowledgeableConditionType_Time = 5117,
			AcknowledgeableConditionType_ReceiveTime = 5118,
			AcknowledgeableConditionType_LocalTime = 5119,
			AcknowledgeableConditionType_Message = 5120,
			AcknowledgeableConditionType_Severity = 5121,
			AcknowledgeableConditionType_Retain = 5122,
			AcknowledgeableConditionType_ConditionRefresh = 5123,
			AcknowledgeableConditionType_ConditionRefresh_InputArguments = 5124,
			AlarmConditionType_EventId = 5540,
			AlarmConditionType_EventType = 5541,
			AlarmConditionType_SourceNode = 5542,
			AlarmConditionType_SourceName = 5543,
			AlarmConditionType_Time = 5544,
			AlarmConditionType_ReceiveTime = 5545,
			AlarmConditionType_LocalTime = 5546,
			AlarmConditionType_Message = 5547,
			AlarmConditionType_Severity = 5548,
			AlarmConditionType_Retain = 5549,
			AlarmConditionType_ConditionRefresh = 5550,
			AlarmConditionType_ConditionRefresh_InputArguments = 5551,
			ShelvedStateMachineType_CurrentState = 6088,
			ShelvedStateMachineType_CurrentState_Id = 6089,
			ShelvedStateMachineType_CurrentState_Name = 6090,
			ShelvedStateMachineType_CurrentState_Number = 6091,
			ShelvedStateMachineType_CurrentState_EffectiveDisplayName = 6092,
			ShelvedStateMachineType_LastTransition = 6093,
			ShelvedStateMachineType_LastTransition_Id = 6094,
			ShelvedStateMachineType_LastTransition_Name = 6095,
			ShelvedStateMachineType_LastTransition_Number = 6096,
			ShelvedStateMachineType_LastTransition_TransitionTime = 6097,
			ShelvedStateMachineType_Unshelved_StateNumber = 6098,
			ShelvedStateMachineType_TimedShelved_StateNumber = 6100,
			ShelvedStateMachineType_OneShotShelved_StateNumber = 6101,
			TimedShelveMethodType = 6102,
			TimedShelveMethodType_InputArguments = 6103,
			LimitAlarmType_EventId = 6116,
			LimitAlarmType_EventType = 6117,
			LimitAlarmType_SourceNode = 6118,
			LimitAlarmType_SourceName = 6119,
			LimitAlarmType_Time = 6120,
			LimitAlarmType_ReceiveTime = 6121,
			LimitAlarmType_LocalTime = 6122,
			LimitAlarmType_Message = 6123,
			LimitAlarmType_Severity = 6124,
			LimitAlarmType_Retain = 6125,
			LimitAlarmType_ConditionRefresh = 6126,
			LimitAlarmType_ConditionRefresh_InputArguments = 6127,
			IdType_EnumStrings = 7591,
			EnumValueType = 7594,
			MessageSecurityMode_EnumStrings = 7595,
			UserTokenType_EnumStrings = 7596,
			ApplicationType_EnumStrings = 7597,
			SecurityTokenRequestType_EnumStrings = 7598,
			ComplianceLevel_EnumStrings = 7599,
			BrowseDirection_EnumStrings = 7603,
			FilterOperator_EnumStrings = 7605,
			TimestampsToReturn_EnumStrings = 7606,
			MonitoringMode_EnumStrings = 7608,
			DataChangeTrigger_EnumStrings = 7609,
			DeadbandType_EnumStrings = 7610,
			RedundancySupport_EnumStrings = 7611,
			ServerState_EnumStrings = 7612,
			ExceptionDeviationFormat_EnumStrings = 7614,
			EnumValueType_Encoding_DefaultXml = 7616,
			BinarySchema = 7617,
			BinarySchema_DataTypeVersion = 7618,
			BinarySchema_NamespaceUri = 7619,
			BinarySchema_Argument = 7650,
			BinarySchema_Argument_DataTypeVersion = 7651,
			BinarySchema_Argument_DictionaryFragment = 7652,
			BinarySchema_EnumValueType = 7656,
			BinarySchema_EnumValueType_DataTypeVersion = 7657,
			BinarySchema_EnumValueType_DictionaryFragment = 7658,
			BinarySchema_StatusResult = 7659,
			BinarySchema_StatusResult_DataTypeVersion = 7660,
			BinarySchema_StatusResult_DictionaryFragment = 7661,
			BinarySchema_UserTokenPolicy = 7662,
			BinarySchema_UserTokenPolicy_DataTypeVersion = 7663,
			BinarySchema_UserTokenPolicy_DictionaryFragment = 7664,
			BinarySchema_ApplicationDescription = 7665,
			BinarySchema_ApplicationDescription_DataTypeVersion = 7666,
			BinarySchema_ApplicationDescription_DictionaryFragment = 7667,
			BinarySchema_EndpointDescription = 7668,
			BinarySchema_EndpointDescription_DataTypeVersion = 7669,
			BinarySchema_EndpointDescription_DictionaryFragment = 7670,
			BinarySchema_UserIdentityToken = 7671,
			BinarySchema_UserIdentityToken_DataTypeVersion = 7672,
			BinarySchema_UserIdentityToken_DictionaryFragment = 7673,
			BinarySchema_AnonymousIdentityToken = 7674,
			BinarySchema_AnonymousIdentityToken_DataTypeVersion = 7675,
			BinarySchema_AnonymousIdentityToken_DictionaryFragment = 7676,
			BinarySchema_UserNameIdentityToken = 7677,
			BinarySchema_UserNameIdentityToken_DataTypeVersion = 7678,
			BinarySchema_UserNameIdentityToken_DictionaryFragment = 7679,
			BinarySchema_X509IdentityToken = 7680,
			BinarySchema_X509IdentityToken_DataTypeVersion = 7681,
			BinarySchema_X509IdentityToken_DictionaryFragment = 7682,
			BinarySchema_IssuedIdentityToken = 7683,
			BinarySchema_IssuedIdentityToken_DataTypeVersion = 7684,
			BinarySchema_IssuedIdentityToken_DictionaryFragment = 7685,
			BinarySchema_EndpointConfiguration = 7686,
			BinarySchema_EndpointConfiguration_DataTypeVersion = 7687,
			BinarySchema_EndpointConfiguration_DictionaryFragment = 7688,
			BinarySchema_SupportedProfile = 7689,
			BinarySchema_SupportedProfile_DataTypeVersion = 7690,
			BinarySchema_SupportedProfile_DictionaryFragment = 7691,
			BinarySchema_BuildInfo = 7692,
			BinarySchema_BuildInfo_DataTypeVersion = 7693,
			BinarySchema_BuildInfo_DictionaryFragment = 7694,
			BinarySchema_SoftwareCertificate = 7695,
			BinarySchema_SoftwareCertificate_DataTypeVersion = 7696,
			BinarySchema_SoftwareCertificate_DictionaryFragment = 7697,
			BinarySchema_SignedSoftwareCertificate = 7698,
			BinarySchema_SignedSoftwareCertificate_DataTypeVersion = 7699,
			BinarySchema_SignedSoftwareCertificate_DictionaryFragment = 7700,
			BinarySchema_AddNodesItem = 7728,
			BinarySchema_AddNodesItem_DataTypeVersion = 7729,
			BinarySchema_AddNodesItem_DictionaryFragment = 7730,
			BinarySchema_AddReferencesItem = 7731,
			BinarySchema_AddReferencesItem_DataTypeVersion = 7732,
			BinarySchema_AddReferencesItem_DictionaryFragment = 7733,
			BinarySchema_DeleteNodesItem = 7734,
			BinarySchema_DeleteNodesItem_DataTypeVersion = 7735,
			BinarySchema_DeleteNodesItem_DictionaryFragment = 7736,
			BinarySchema_DeleteReferencesItem = 7737,
			BinarySchema_DeleteReferencesItem_DataTypeVersion = 7738,
			BinarySchema_DeleteReferencesItem_DictionaryFragment = 7739,
			BinarySchema_ScalarTestType = 7749,
			BinarySchema_ScalarTestType_DataTypeVersion = 7750,
			BinarySchema_ScalarTestType_DictionaryFragment = 7751,
			BinarySchema_ArrayTestType = 7752,
			BinarySchema_ArrayTestType_DataTypeVersion = 7753,
			BinarySchema_ArrayTestType_DictionaryFragment = 7754,
			BinarySchema_CompositeTestType = 7755,
			BinarySchema_CompositeTestType_DataTypeVersion = 7756,
			BinarySchema_CompositeTestType_DictionaryFragment = 7757,
			BinarySchema_RegisteredServer = 7782,
			BinarySchema_RegisteredServer_DataTypeVersion = 7783,
			BinarySchema_RegisteredServer_DictionaryFragment = 7784,
			BinarySchema_ContentFilterElement = 7929,
			BinarySchema_ContentFilterElement_DataTypeVersion = 7930,
			BinarySchema_ContentFilterElement_DictionaryFragment = 7931,
			BinarySchema_ContentFilter = 7932,
			BinarySchema_ContentFilter_DataTypeVersion = 7933,
			BinarySchema_ContentFilter_DictionaryFragment = 7934,
			BinarySchema_FilterOperand = 7935,
			BinarySchema_FilterOperand_DataTypeVersion = 7936,
			BinarySchema_FilterOperand_DictionaryFragment = 7937,
			BinarySchema_ElementOperand = 7938,
			BinarySchema_ElementOperand_DataTypeVersion = 7939,
			BinarySchema_ElementOperand_DictionaryFragment = 7940,
			BinarySchema_LiteralOperand = 7941,
			BinarySchema_LiteralOperand_DataTypeVersion = 7942,
			BinarySchema_LiteralOperand_DictionaryFragment = 7943,
			BinarySchema_AttributeOperand = 7944,
			BinarySchema_AttributeOperand_DataTypeVersion = 7945,
			BinarySchema_AttributeOperand_DictionaryFragment = 7946,
			BinarySchema_SimpleAttributeOperand = 7947,
			BinarySchema_SimpleAttributeOperand_DataTypeVersion = 7948,
			BinarySchema_SimpleAttributeOperand_DictionaryFragment = 7949,
			BinarySchema_HistoryEvent = 8004,
			BinarySchema_HistoryEvent_DataTypeVersion = 8005,
			BinarySchema_HistoryEvent_DictionaryFragment = 8006,
			BinarySchema_MonitoringFilter = 8067,
			BinarySchema_MonitoringFilter_DataTypeVersion = 8068,
			BinarySchema_MonitoringFilter_DictionaryFragment = 8069,
			BinarySchema_EventFilter = 8073,
			BinarySchema_EventFilter_DataTypeVersion = 8074,
			BinarySchema_EventFilter_DictionaryFragment = 8075,
			BinarySchema_AggregateConfiguration = 8076,
			BinarySchema_AggregateConfiguration_DataTypeVersion = 8077,
			BinarySchema_AggregateConfiguration_DictionaryFragment = 8078,
			BinarySchema_HistoryEventFieldList = 8172,
			BinarySchema_HistoryEventFieldList_DataTypeVersion = 8173,
			BinarySchema_HistoryEventFieldList_DictionaryFragment = 8174,
			BinarySchema_RedundantServerDataType = 8208,
			BinarySchema_RedundantServerDataType_DataTypeVersion = 8209,
			BinarySchema_RedundantServerDataType_DictionaryFragment = 8210,
			BinarySchema_SamplingIntervalDiagnosticsDataType = 8211,
			BinarySchema_SamplingIntervalDiagnosticsDataType_DataTypeVersion = 8212,
			BinarySchema_SamplingIntervalDiagnosticsDataType_DictionaryFragment = 8213,
			BinarySchema_ServerDiagnosticsSummaryDataType = 8214,
			BinarySchema_ServerDiagnosticsSummaryDataType_DataTypeVersion = 8215,
			BinarySchema_ServerDiagnosticsSummaryDataType_DictionaryFragment = 8216,
			BinarySchema_ServerStatusDataType = 8217,
			BinarySchema_ServerStatusDataType_DataTypeVersion = 8218,
			BinarySchema_ServerStatusDataType_DictionaryFragment = 8219,
			BinarySchema_SessionDiagnosticsDataType = 8220,
			BinarySchema_SessionDiagnosticsDataType_DataTypeVersion = 8221,
			BinarySchema_SessionDiagnosticsDataType_DictionaryFragment = 8222,
			BinarySchema_SessionSecurityDiagnosticsDataType = 8223,
			BinarySchema_SessionSecurityDiagnosticsDataType_DataTypeVersion = 8224,
			BinarySchema_SessionSecurityDiagnosticsDataType_DictionaryFragment = 8225,
			BinarySchema_ServiceCounterDataType = 8226,
			BinarySchema_ServiceCounterDataType_DataTypeVersion = 8227,
			BinarySchema_ServiceCounterDataType_DictionaryFragment = 8228,
			BinarySchema_SubscriptionDiagnosticsDataType = 8229,
			BinarySchema_SubscriptionDiagnosticsDataType_DataTypeVersion = 8230,
			BinarySchema_SubscriptionDiagnosticsDataType_DictionaryFragment = 8231,
			BinarySchema_ModelChangeStructureDataType = 8232,
			BinarySchema_ModelChangeStructureDataType_DataTypeVersion = 8233,
			BinarySchema_ModelChangeStructureDataType_DictionaryFragment = 8234,
			BinarySchema_SemanticChangeStructureDataType = 8235,
			BinarySchema_SemanticChangeStructureDataType_DataTypeVersion = 8236,
			BinarySchema_SemanticChangeStructureDataType_DictionaryFragment = 8237,
			BinarySchema_Range = 8238,
			BinarySchema_Range_DataTypeVersion = 8239,
			BinarySchema_Range_DictionaryFragment = 8240,
			BinarySchema_EUInformation = 8241,
			BinarySchema_EUInformation_DataTypeVersion = 8242,
			BinarySchema_EUInformation_DictionaryFragment = 8243,
			BinarySchema_Annotation = 8244,
			BinarySchema_Annotation_DataTypeVersion = 8245,
			BinarySchema_Annotation_DictionaryFragment = 8246,
			BinarySchema_ProgramDiagnosticDataType = 8247,
			BinarySchema_ProgramDiagnosticDataType_DataTypeVersion = 8248,
			BinarySchema_ProgramDiagnosticDataType_DictionaryFragment = 8249,
			EnumValueType_Encoding_DefaultBinary = 8251,
			XmlSchema = 8252,
			XmlSchema_DataTypeVersion = 8253,
			XmlSchema_NamespaceUri = 8254,
			XmlSchema_Argument = 8285,
			XmlSchema_Argument_DataTypeVersion = 8286,
			XmlSchema_Argument_DictionaryFragment = 8287,
			XmlSchema_EnumValueType = 8291,
			XmlSchema_EnumValueType_DataTypeVersion = 8292,
			XmlSchema_EnumValueType_DictionaryFragment = 8293,
			XmlSchema_StatusResult = 8294,
			XmlSchema_StatusResult_DataTypeVersion = 8295,
			XmlSchema_StatusResult_DictionaryFragment = 8296,
			XmlSchema_UserTokenPolicy = 8297,
			XmlSchema_UserTokenPolicy_DataTypeVersion = 8298,
			XmlSchema_UserTokenPolicy_DictionaryFragment = 8299,
			XmlSchema_ApplicationDescription = 8300,
			XmlSchema_ApplicationDescription_DataTypeVersion = 8301,
			XmlSchema_ApplicationDescription_DictionaryFragment = 8302,
			XmlSchema_EndpointDescription = 8303,
			XmlSchema_EndpointDescription_DataTypeVersion = 8304,
			XmlSchema_EndpointDescription_DictionaryFragment = 8305,
			XmlSchema_UserIdentityToken = 8306,
			XmlSchema_UserIdentityToken_DataTypeVersion = 8307,
			XmlSchema_UserIdentityToken_DictionaryFragment = 8308,
			XmlSchema_AnonymousIdentityToken = 8309,
			XmlSchema_AnonymousIdentityToken_DataTypeVersion = 8310,
			XmlSchema_AnonymousIdentityToken_DictionaryFragment = 8311,
			XmlSchema_UserNameIdentityToken = 8312,
			XmlSchema_UserNameIdentityToken_DataTypeVersion = 8313,
			XmlSchema_UserNameIdentityToken_DictionaryFragment = 8314,
			XmlSchema_X509IdentityToken = 8315,
			XmlSchema_X509IdentityToken_DataTypeVersion = 8316,
			XmlSchema_X509IdentityToken_DictionaryFragment = 8317,
			XmlSchema_IssuedIdentityToken = 8318,
			XmlSchema_IssuedIdentityToken_DataTypeVersion = 8319,
			XmlSchema_IssuedIdentityToken_DictionaryFragment = 8320,
			XmlSchema_EndpointConfiguration = 8321,
			XmlSchema_EndpointConfiguration_DataTypeVersion = 8322,
			XmlSchema_EndpointConfiguration_DictionaryFragment = 8323,
			XmlSchema_SupportedProfile = 8324,
			XmlSchema_SupportedProfile_DataTypeVersion = 8325,
			XmlSchema_SupportedProfile_DictionaryFragment = 8326,
			XmlSchema_BuildInfo = 8327,
			XmlSchema_BuildInfo_DataTypeVersion = 8328,
			XmlSchema_BuildInfo_DictionaryFragment = 8329,
			XmlSchema_SoftwareCertificate = 8330,
			XmlSchema_SoftwareCertificate_DataTypeVersion = 8331,
			XmlSchema_SoftwareCertificate_DictionaryFragment = 8332,
			XmlSchema_SignedSoftwareCertificate = 8333,
			XmlSchema_SignedSoftwareCertificate_DataTypeVersion = 8334,
			XmlSchema_SignedSoftwareCertificate_DictionaryFragment = 8335,
			XmlSchema_AddNodesItem = 8363,
			XmlSchema_AddNodesItem_DataTypeVersion = 8364,
			XmlSchema_AddNodesItem_DictionaryFragment = 8365,
			XmlSchema_AddReferencesItem = 8366,
			XmlSchema_AddReferencesItem_DataTypeVersion = 8367,
			XmlSchema_AddReferencesItem_DictionaryFragment = 8368,
			XmlSchema_DeleteNodesItem = 8369,
			XmlSchema_DeleteNodesItem_DataTypeVersion = 8370,
			XmlSchema_DeleteNodesItem_DictionaryFragment = 8371,
			XmlSchema_DeleteReferencesItem = 8372,
			XmlSchema_DeleteReferencesItem_DataTypeVersion = 8373,
			XmlSchema_DeleteReferencesItem_DictionaryFragment = 8374,
			XmlSchema_ScalarTestType = 8384,
			XmlSchema_ScalarTestType_DataTypeVersion = 8385,
			XmlSchema_ScalarTestType_DictionaryFragment = 8386,
			XmlSchema_ArrayTestType = 8387,
			XmlSchema_ArrayTestType_DataTypeVersion = 8388,
			XmlSchema_ArrayTestType_DictionaryFragment = 8389,
			XmlSchema_CompositeTestType = 8390,
			XmlSchema_CompositeTestType_DataTypeVersion = 8391,
			XmlSchema_CompositeTestType_DictionaryFragment = 8392,
			XmlSchema_RegisteredServer = 8417,
			XmlSchema_RegisteredServer_DataTypeVersion = 8418,
			XmlSchema_RegisteredServer_DictionaryFragment = 8419,
			XmlSchema_ContentFilterElement = 8564,
			XmlSchema_ContentFilterElement_DataTypeVersion = 8565,
			XmlSchema_ContentFilterElement_DictionaryFragment = 8566,
			XmlSchema_ContentFilter = 8567,
			XmlSchema_ContentFilter_DataTypeVersion = 8568,
			XmlSchema_ContentFilter_DictionaryFragment = 8569,
			XmlSchema_FilterOperand = 8570,
			XmlSchema_FilterOperand_DataTypeVersion = 8571,
			XmlSchema_FilterOperand_DictionaryFragment = 8572,
			XmlSchema_ElementOperand = 8573,
			XmlSchema_ElementOperand_DataTypeVersion = 8574,
			XmlSchema_ElementOperand_DictionaryFragment = 8575,
			XmlSchema_LiteralOperand = 8576,
			XmlSchema_LiteralOperand_DataTypeVersion = 8577,
			XmlSchema_LiteralOperand_DictionaryFragment = 8578,
			XmlSchema_AttributeOperand = 8579,
			XmlSchema_AttributeOperand_DataTypeVersion = 8580,
			XmlSchema_AttributeOperand_DictionaryFragment = 8581,
			XmlSchema_SimpleAttributeOperand = 8582,
			XmlSchema_SimpleAttributeOperand_DataTypeVersion = 8583,
			XmlSchema_SimpleAttributeOperand_DictionaryFragment = 8584,
			XmlSchema_HistoryEvent = 8639,
			XmlSchema_HistoryEvent_DataTypeVersion = 8640,
			XmlSchema_HistoryEvent_DictionaryFragment = 8641,
			XmlSchema_MonitoringFilter = 8702,
			XmlSchema_MonitoringFilter_DataTypeVersion = 8703,
			XmlSchema_MonitoringFilter_DictionaryFragment = 8704,
			XmlSchema_EventFilter = 8708,
			XmlSchema_EventFilter_DataTypeVersion = 8709,
			XmlSchema_EventFilter_DictionaryFragment = 8710,
			XmlSchema_AggregateConfiguration = 8711,
			XmlSchema_AggregateConfiguration_DataTypeVersion = 8712,
			XmlSchema_AggregateConfiguration_DictionaryFragment = 8713,
			XmlSchema_HistoryEventFieldList = 8807,
			XmlSchema_HistoryEventFieldList_DataTypeVersion = 8808,
			XmlSchema_HistoryEventFieldList_DictionaryFragment = 8809,
			XmlSchema_RedundantServerDataType = 8843,
			XmlSchema_RedundantServerDataType_DataTypeVersion = 8844,
			XmlSchema_RedundantServerDataType_DictionaryFragment = 8845,
			XmlSchema_SamplingIntervalDiagnosticsDataType = 8846,
			XmlSchema_SamplingIntervalDiagnosticsDataType_DataTypeVersion = 8847,
			XmlSchema_SamplingIntervalDiagnosticsDataType_DictionaryFragment = 8848,
			XmlSchema_ServerDiagnosticsSummaryDataType = 8849,
			XmlSchema_ServerDiagnosticsSummaryDataType_DataTypeVersion = 8850,
			XmlSchema_ServerDiagnosticsSummaryDataType_DictionaryFragment = 8851,
			XmlSchema_ServerStatusDataType = 8852,
			XmlSchema_ServerStatusDataType_DataTypeVersion = 8853,
			XmlSchema_ServerStatusDataType_DictionaryFragment = 8854,
			XmlSchema_SessionDiagnosticsDataType = 8855,
			XmlSchema_SessionDiagnosticsDataType_DataTypeVersion = 8856,
			XmlSchema_SessionDiagnosticsDataType_DictionaryFragment = 8857,
			XmlSchema_SessionSecurityDiagnosticsDataType = 8858,
			XmlSchema_SessionSecurityDiagnosticsDataType_DataTypeVersion = 8859,
			XmlSchema_SessionSecurityDiagnosticsDataType_DictionaryFragment = 8860,
			XmlSchema_ServiceCounterDataType = 8861,
			XmlSchema_ServiceCounterDataType_DataTypeVersion = 8862,
			XmlSchema_ServiceCounterDataType_DictionaryFragment = 8863,
			XmlSchema_SubscriptionDiagnosticsDataType = 8864,
			XmlSchema_SubscriptionDiagnosticsDataType_DataTypeVersion = 8865,
			XmlSchema_SubscriptionDiagnosticsDataType_DictionaryFragment = 8866,
			XmlSchema_ModelChangeStructureDataType = 8867,
			XmlSchema_ModelChangeStructureDataType_DataTypeVersion = 8868,
			XmlSchema_ModelChangeStructureDataType_DictionaryFragment = 8869,
			XmlSchema_SemanticChangeStructureDataType = 8870,
			XmlSchema_SemanticChangeStructureDataType_DataTypeVersion = 8871,
			XmlSchema_SemanticChangeStructureDataType_DictionaryFragment = 8872,
			XmlSchema_Range = 8873,
			XmlSchema_Range_DataTypeVersion = 8874,
			XmlSchema_Range_DictionaryFragment = 8875,
			XmlSchema_EUInformation = 8876,
			XmlSchema_EUInformation_DataTypeVersion = 8877,
			XmlSchema_EUInformation_DictionaryFragment = 8878,
			XmlSchema_Annotation = 8879,
			XmlSchema_Annotation_DataTypeVersion = 8880,
			XmlSchema_Annotation_DictionaryFragment = 8881,
			XmlSchema_ProgramDiagnosticDataType = 8882,
			XmlSchema_ProgramDiagnosticDataType_DataTypeVersion = 8883,
			XmlSchema_ProgramDiagnosticDataType_DictionaryFragment = 8884,
			SubscriptionDiagnosticsType_MaxLifetimeCount = 8888,
			SubscriptionDiagnosticsType_LatePublishRequestCount = 8889,
			SubscriptionDiagnosticsType_CurrentKeepAliveCount = 8890,
			SubscriptionDiagnosticsType_CurrentLifetimeCount = 8891,
			SubscriptionDiagnosticsType_UnacknowledgedMessageCount = 8892,
			SubscriptionDiagnosticsType_DiscardedMessageCount = 8893,
			SubscriptionDiagnosticsType_MonitoredItemCount = 8894,
			SubscriptionDiagnosticsType_DisabledMonitoredItemCount = 8895,
			SubscriptionDiagnosticsType_MonitoringQueueOverflowCount = 8896,
			SubscriptionDiagnosticsType_NextSequenceNumber = 8897,
			SessionDiagnosticsObjectType_SessionDiagnostics_TotalRequestCount = 8898,
			SessionDiagnosticsVariableType_TotalRequestCount = 8900,
			SubscriptionDiagnosticsType_EventQueueOverFlowCount = 8902,
			TimeZoneDataType = 8912,
			TimeZoneDataType_Encoding_DefaultXml = 8913,
			BinarySchema_TimeZoneDataType = 8914,
			BinarySchema_TimeZoneDataType_DataTypeVersion = 8915,
			BinarySchema_TimeZoneDataType_DictionaryFragment = 8916,
			TimeZoneDataType_Encoding_DefaultBinary = 8917,
			XmlSchema_TimeZoneDataType = 8918,
			XmlSchema_TimeZoneDataType_DataTypeVersion = 8919,
			XmlSchema_TimeZoneDataType_DictionaryFragment = 8920,
			LockType = 8921,
			LockType_Lock = 8922,
			LockType_Unlock = 8923,
			ServerLock = 8924,
			ServerLock_Lock = 8925,
			ServerLock_Unlock = 8926,
			AuditConditionRespondEventType = 8927,
			AuditConditionRespondEventType_EventId = 8928,
			AuditConditionRespondEventType_EventType = 8929,
			AuditConditionRespondEventType_SourceNode = 8930,
			AuditConditionRespondEventType_SourceName = 8931,
			AuditConditionRespondEventType_Time = 8932,
			AuditConditionRespondEventType_ReceiveTime = 8933,
			AuditConditionRespondEventType_LocalTime = 8934,
			AuditConditionRespondEventType_Message = 8935,
			AuditConditionRespondEventType_Severity = 8936,
			AuditConditionRespondEventType_ActionTimeStamp = 8937,
			AuditConditionRespondEventType_Status = 8938,
			AuditConditionRespondEventType_ServerId = 8939,
			AuditConditionRespondEventType_ClientAuditEntryId = 8940,
			AuditConditionRespondEventType_ClientUserId = 8941,
			AuditConditionRespondEventType_MethodId = 8942,
			AuditConditionRespondEventType_InputArguments = 8943,
			AuditConditionAcknowledgeEventType = 8944,
			AuditConditionAcknowledgeEventType_EventId = 8945,
			AuditConditionAcknowledgeEventType_EventType = 8946,
			AuditConditionAcknowledgeEventType_SourceNode = 8947,
			AuditConditionAcknowledgeEventType_SourceName = 8948,
			AuditConditionAcknowledgeEventType_Time = 8949,
			AuditConditionAcknowledgeEventType_ReceiveTime = 8950,
			AuditConditionAcknowledgeEventType_LocalTime = 8951,
			AuditConditionAcknowledgeEventType_Message = 8952,
			AuditConditionAcknowledgeEventType_Severity = 8953,
			AuditConditionAcknowledgeEventType_ActionTimeStamp = 8954,
			AuditConditionAcknowledgeEventType_Status = 8955,
			AuditConditionAcknowledgeEventType_ServerId = 8956,
			AuditConditionAcknowledgeEventType_ClientAuditEntryId = 8957,
			AuditConditionAcknowledgeEventType_ClientUserId = 8958,
			AuditConditionAcknowledgeEventType_MethodId = 8959,
			AuditConditionAcknowledgeEventType_InputArguments = 8960,
			AuditConditionConfirmEventType = 8961,
			AuditConditionConfirmEventType_EventId = 8962,
			AuditConditionConfirmEventType_EventType = 8963,
			AuditConditionConfirmEventType_SourceNode = 8964,
			AuditConditionConfirmEventType_SourceName = 8965,
			AuditConditionConfirmEventType_Time = 8966,
			AuditConditionConfirmEventType_ReceiveTime = 8967,
			AuditConditionConfirmEventType_LocalTime = 8968,
			AuditConditionConfirmEventType_Message = 8969,
			AuditConditionConfirmEventType_Severity = 8970,
			AuditConditionConfirmEventType_ActionTimeStamp = 8971,
			AuditConditionConfirmEventType_Status = 8972,
			AuditConditionConfirmEventType_ServerId = 8973,
			AuditConditionConfirmEventType_ClientAuditEntryId = 8974,
			AuditConditionConfirmEventType_ClientUserId = 8975,
			AuditConditionConfirmEventType_MethodId = 8976,
			AuditConditionConfirmEventType_InputArguments = 8977,
			TwoStateVariableType = 8995,
			TwoStateVariableType_Id = 8996,
			TwoStateVariableType_Name = 8997,
			TwoStateVariableType_Number = 8998,
			TwoStateVariableType_EffectiveDisplayName = 8999,
			TwoStateVariableType_TransitionTime = 9000,
			TwoStateVariableType_EffectiveTransitionTime = 9001,
			ConditionVariableType = 9002,
			ConditionVariableType_SourceTimestamp = 9003,
			HasTrueSubState = 9004,
			HasFalseSubState = 9005,
			HasCondition = 9006,
			ConditionRefreshMethodType = 9007,
			ConditionRefreshMethodType_InputArguments = 9008,
			ConditionType_ConditionName = 9009,
			ConditionType_BranchId = 9010,
			ConditionType_EnabledState = 9011,
			ConditionType_EnabledState_Id = 9012,
			ConditionType_EnabledState_Name = 9013,
			ConditionType_EnabledState_Number = 9014,
			ConditionType_EnabledState_EffectiveDisplayName = 9015,
			ConditionType_EnabledState_TransitionTime = 9016,
			ConditionType_EnabledState_EffectiveTransitionTime = 9017,
			ConditionType_EnabledState_TrueState = 9018,
			ConditionType_EnabledState_FalseState = 9019,
			ConditionType_Quality = 9020,
			ConditionType_Quality_SourceTimestamp = 9021,
			ConditionType_LastSeverity = 9022,
			ConditionType_LastSeverity_SourceTimestamp = 9023,
			ConditionType_Comment = 9024,
			ConditionType_Comment_SourceTimestamp = 9025,
			ConditionType_ClientUserId = 9026,
			ConditionType_Enable = 9027,
			ConditionType_Disable = 9028,
			ConditionType_AddComment = 9029,
			ConditionType_AddComment_InputArguments = 9030,
			DialogResponseMethodType = 9031,
			DialogResponseMethodType_InputArguments = 9032,
			DialogConditionType_ConditionName = 9033,
			DialogConditionType_BranchId = 9034,
			DialogConditionType_EnabledState = 9035,
			DialogConditionType_EnabledState_Id = 9036,
			DialogConditionType_EnabledState_Name = 9037,
			DialogConditionType_EnabledState_Number = 9038,
			DialogConditionType_EnabledState_EffectiveDisplayName = 9039,
			DialogConditionType_EnabledState_TransitionTime = 9040,
			DialogConditionType_EnabledState_EffectiveTransitionTime = 9041,
			DialogConditionType_EnabledState_TrueState = 9042,
			DialogConditionType_EnabledState_FalseState = 9043,
			DialogConditionType_Quality = 9044,
			DialogConditionType_Quality_SourceTimestamp = 9045,
			DialogConditionType_LastSeverity = 9046,
			DialogConditionType_LastSeverity_SourceTimestamp = 9047,
			DialogConditionType_Comment = 9048,
			DialogConditionType_Comment_SourceTimestamp = 9049,
			DialogConditionType_ClientUserId = 9050,
			DialogConditionType_Enable = 9051,
			DialogConditionType_Disable = 9052,
			DialogConditionType_AddComment = 9053,
			DialogConditionType_AddComment_InputArguments = 9054,
			DialogConditionType_DialogState = 9055,
			DialogConditionType_DialogState_Id = 9056,
			DialogConditionType_DialogState_Name = 9057,
			DialogConditionType_DialogState_Number = 9058,
			DialogConditionType_DialogState_EffectiveDisplayName = 9059,
			DialogConditionType_DialogState_TransitionTime = 9060,
			DialogConditionType_DialogState_EffectiveTransitionTime = 9061,
			DialogConditionType_DialogState_TrueState = 9062,
			DialogConditionType_DialogState_FalseState = 9063,
			DialogConditionType_ResponseOptionSet = 9064,
			DialogConditionType_DefaultResponse = 9065,
			DialogConditionType_OkResponse = 9066,
			DialogConditionType_CancelResponse = 9067,
			DialogConditionType_LastResponse = 9068,
			DialogConditionType_Respond = 9069,
			DialogConditionType_Respond_InputArguments = 9070,
			AcknowledgeableConditionType_ConditionName = 9071,
			AcknowledgeableConditionType_BranchId = 9072,
			AcknowledgeableConditionType_EnabledState = 9073,
			AcknowledgeableConditionType_EnabledState_Id = 9074,
			AcknowledgeableConditionType_EnabledState_Name = 9075,
			AcknowledgeableConditionType_EnabledState_Number = 9076,
			AcknowledgeableConditionType_EnabledState_EffectiveDisplayName = 9077,
			AcknowledgeableConditionType_EnabledState_TransitionTime = 9078,
			AcknowledgeableConditionType_EnabledState_EffectiveTransitionTime = 9079,
			AcknowledgeableConditionType_EnabledState_TrueState = 9080,
			AcknowledgeableConditionType_EnabledState_FalseState = 9081,
			AcknowledgeableConditionType_Quality = 9082,
			AcknowledgeableConditionType_Quality_SourceTimestamp = 9083,
			AcknowledgeableConditionType_LastSeverity = 9084,
			AcknowledgeableConditionType_LastSeverity_SourceTimestamp = 9085,
			AcknowledgeableConditionType_Comment = 9086,
			AcknowledgeableConditionType_Comment_SourceTimestamp = 9087,
			AcknowledgeableConditionType_ClientUserId = 9088,
			AcknowledgeableConditionType_Enable = 9089,
			AcknowledgeableConditionType_Disable = 9090,
			AcknowledgeableConditionType_AddComment = 9091,
			AcknowledgeableConditionType_AddComment_InputArguments = 9092,
			AcknowledgeableConditionType_AckedState = 9093,
			AcknowledgeableConditionType_AckedState_Id = 9094,
			AcknowledgeableConditionType_AckedState_Name = 9095,
			AcknowledgeableConditionType_AckedState_Number = 9096,
			AcknowledgeableConditionType_AckedState_EffectiveDisplayName = 9097,
			AcknowledgeableConditionType_AckedState_TransitionTime = 9098,
			AcknowledgeableConditionType_AckedState_EffectiveTransitionTime = 9099,
			AcknowledgeableConditionType_AckedState_TrueState = 9100,
			AcknowledgeableConditionType_AckedState_FalseState = 9101,
			AcknowledgeableConditionType_ConfirmedState = 9102,
			AcknowledgeableConditionType_ConfirmedState_Id = 9103,
			AcknowledgeableConditionType_ConfirmedState_Name = 9104,
			AcknowledgeableConditionType_ConfirmedState_Number = 9105,
			AcknowledgeableConditionType_ConfirmedState_EffectiveDisplayName = 9106,
			AcknowledgeableConditionType_ConfirmedState_TransitionTime = 9107,
			AcknowledgeableConditionType_ConfirmedState_EffectiveTransitionTime = 9108,
			AcknowledgeableConditionType_ConfirmedState_TrueState = 9109,
			AcknowledgeableConditionType_ConfirmedState_FalseState = 9110,
			AcknowledgeableConditionType_Acknowledge = 9111,
			AcknowledgeableConditionType_Acknowledge_InputArguments = 9112,
			AcknowledgeableConditionType_Confirm = 9113,
			AcknowledgeableConditionType_Confirm_InputArguments = 9114,
			ShelvedStateMachineType_UnshelveTime = 9115,
			AlarmConditionType_ConditionName = 9116,
			AlarmConditionType_BranchId = 9117,
			AlarmConditionType_EnabledState = 9118,
			AlarmConditionType_EnabledState_Id = 9119,
			AlarmConditionType_EnabledState_Name = 9120,
			AlarmConditionType_EnabledState_Number = 9121,
			AlarmConditionType_EnabledState_EffectiveDisplayName = 9122,
			AlarmConditionType_EnabledState_TransitionTime = 9123,
			AlarmConditionType_EnabledState_EffectiveTransitionTime = 9124,
			AlarmConditionType_EnabledState_TrueState = 9125,
			AlarmConditionType_EnabledState_FalseState = 9126,
			AlarmConditionType_Quality = 9127,
			AlarmConditionType_Quality_SourceTimestamp = 9128,
			AlarmConditionType_LastSeverity = 9129,
			AlarmConditionType_LastSeverity_SourceTimestamp = 9130,
			AlarmConditionType_Comment = 9131,
			AlarmConditionType_Comment_SourceTimestamp = 9132,
			AlarmConditionType_ClientUserId = 9133,
			AlarmConditionType_Enable = 9134,
			AlarmConditionType_Disable = 9135,
			AlarmConditionType_AddComment = 9136,
			AlarmConditionType_AddComment_InputArguments = 9137,
			AlarmConditionType_AckedState = 9138,
			AlarmConditionType_AckedState_Id = 9139,
			AlarmConditionType_AckedState_Name = 9140,
			AlarmConditionType_AckedState_Number = 9141,
			AlarmConditionType_AckedState_EffectiveDisplayName = 9142,
			AlarmConditionType_AckedState_TransitionTime = 9143,
			AlarmConditionType_AckedState_EffectiveTransitionTime = 9144,
			AlarmConditionType_AckedState_TrueState = 9145,
			AlarmConditionType_AckedState_FalseState = 9146,
			AlarmConditionType_ConfirmedState = 9147,
			AlarmConditionType_ConfirmedState_Id = 9148,
			AlarmConditionType_ConfirmedState_Name = 9149,
			AlarmConditionType_ConfirmedState_Number = 9150,
			AlarmConditionType_ConfirmedState_EffectiveDisplayName = 9151,
			AlarmConditionType_ConfirmedState_TransitionTime = 9152,
			AlarmConditionType_ConfirmedState_EffectiveTransitionTime = 9153,
			AlarmConditionType_ConfirmedState_TrueState = 9154,
			AlarmConditionType_ConfirmedState_FalseState = 9155,
			AlarmConditionType_Acknowledge = 9156,
			AlarmConditionType_Acknowledge_InputArguments = 9157,
			AlarmConditionType_Confirm = 9158,
			AlarmConditionType_Confirm_InputArguments = 9159,
			AlarmConditionType_ActiveState = 9160,
			AlarmConditionType_ActiveState_Id = 9161,
			AlarmConditionType_ActiveState_Name = 9162,
			AlarmConditionType_ActiveState_Number = 9163,
			AlarmConditionType_ActiveState_EffectiveDisplayName = 9164,
			AlarmConditionType_ActiveState_TransitionTime = 9165,
			AlarmConditionType_ActiveState_EffectiveTransitionTime = 9166,
			AlarmConditionType_ActiveState_TrueState = 9167,
			AlarmConditionType_ActiveState_FalseState = 9168,
			AlarmConditionType_SuppressedState = 9169,
			AlarmConditionType_SuppressedState_Id = 9170,
			AlarmConditionType_SuppressedState_Name = 9171,
			AlarmConditionType_SuppressedState_Number = 9172,
			AlarmConditionType_SuppressedState_EffectiveDisplayName = 9173,
			AlarmConditionType_SuppressedState_TransitionTime = 9174,
			AlarmConditionType_SuppressedState_EffectiveTransitionTime = 9175,
			AlarmConditionType_SuppressedState_TrueState = 9176,
			AlarmConditionType_SuppressedState_FalseState = 9177,
			AlarmConditionType_ShelvingState = 9178,
			AlarmConditionType_ShelvingState_CurrentState = 9179,
			AlarmConditionType_ShelvingState_CurrentState_Id = 9180,
			AlarmConditionType_ShelvingState_CurrentState_Name = 9181,
			AlarmConditionType_ShelvingState_CurrentState_Number = 9182,
			AlarmConditionType_ShelvingState_CurrentState_EffectiveDisplayName = 9183,
			AlarmConditionType_ShelvingState_LastTransition = 9184,
			AlarmConditionType_ShelvingState_LastTransition_Id = 9185,
			AlarmConditionType_ShelvingState_LastTransition_Name = 9186,
			AlarmConditionType_ShelvingState_LastTransition_Number = 9187,
			AlarmConditionType_ShelvingState_LastTransition_TransitionTime = 9188,
			AlarmConditionType_ShelvingState_UnshelveTime = 9189,
			AlarmConditionType_ShelvingState_Unshelve = 9211,
			AlarmConditionType_ShelvingState_OneShotShelve = 9212,
			AlarmConditionType_ShelvingState_TimedShelve = 9213,
			AlarmConditionType_ShelvingState_TimedShelve_InputArguments = 9214,
			AlarmConditionType_SuppressedOrShelved = 9215,
			AlarmConditionType_MaxTimeShelved = 9216,
			LimitAlarmType_ConditionName = 9217,
			LimitAlarmType_BranchId = 9218,
			LimitAlarmType_EnabledState = 9219,
			LimitAlarmType_EnabledState_Id = 9220,
			LimitAlarmType_EnabledState_Name = 9221,
			LimitAlarmType_EnabledState_Number = 9222,
			LimitAlarmType_EnabledState_EffectiveDisplayName = 9223,
			LimitAlarmType_EnabledState_TransitionTime = 9224,
			LimitAlarmType_EnabledState_EffectiveTransitionTime = 9225,
			LimitAlarmType_EnabledState_TrueState = 9226,
			LimitAlarmType_EnabledState_FalseState = 9227,
			LimitAlarmType_Quality = 9228,
			LimitAlarmType_Quality_SourceTimestamp = 9229,
			LimitAlarmType_LastSeverity = 9230,
			LimitAlarmType_LastSeverity_SourceTimestamp = 9231,
			LimitAlarmType_Comment = 9232,
			LimitAlarmType_Comment_SourceTimestamp = 9233,
			LimitAlarmType_ClientUserId = 9234,
			LimitAlarmType_Enable = 9235,
			LimitAlarmType_Disable = 9236,
			LimitAlarmType_AddComment = 9237,
			LimitAlarmType_AddComment_InputArguments = 9238,
			LimitAlarmType_AckedState = 9239,
			LimitAlarmType_AckedState_Id = 9240,
			LimitAlarmType_AckedState_Name = 9241,
			LimitAlarmType_AckedState_Number = 9242,
			LimitAlarmType_AckedState_EffectiveDisplayName = 9243,
			LimitAlarmType_AckedState_TransitionTime = 9244,
			LimitAlarmType_AckedState_EffectiveTransitionTime = 9245,
			LimitAlarmType_AckedState_TrueState = 9246,
			LimitAlarmType_AckedState_FalseState = 9247,
			LimitAlarmType_ConfirmedState = 9248,
			LimitAlarmType_ConfirmedState_Id = 9249,
			LimitAlarmType_ConfirmedState_Name = 9250,
			LimitAlarmType_ConfirmedState_Number = 9251,
			LimitAlarmType_ConfirmedState_EffectiveDisplayName = 9252,
			LimitAlarmType_ConfirmedState_TransitionTime = 9253,
			LimitAlarmType_ConfirmedState_EffectiveTransitionTime = 9254,
			LimitAlarmType_ConfirmedState_TrueState = 9255,
			LimitAlarmType_ConfirmedState_FalseState = 9256,
			LimitAlarmType_Acknowledge = 9257,
			LimitAlarmType_Acknowledge_InputArguments = 9258,
			LimitAlarmType_Confirm = 9259,
			LimitAlarmType_Confirm_InputArguments = 9260,
			LimitAlarmType_ActiveState = 9261,
			LimitAlarmType_ActiveState_Id = 9262,
			LimitAlarmType_ActiveState_Name = 9263,
			LimitAlarmType_ActiveState_Number = 9264,
			LimitAlarmType_ActiveState_EffectiveDisplayName = 9265,
			LimitAlarmType_ActiveState_TransitionTime = 9266,
			LimitAlarmType_ActiveState_EffectiveTransitionTime = 9267,
			LimitAlarmType_ActiveState_TrueState = 9268,
			LimitAlarmType_ActiveState_FalseState = 9269,
			LimitAlarmType_SuppressedState = 9270,
			LimitAlarmType_SuppressedState_Id = 9271,
			LimitAlarmType_SuppressedState_Name = 9272,
			LimitAlarmType_SuppressedState_Number = 9273,
			LimitAlarmType_SuppressedState_EffectiveDisplayName = 9274,
			LimitAlarmType_SuppressedState_TransitionTime = 9275,
			LimitAlarmType_SuppressedState_EffectiveTransitionTime = 9276,
			LimitAlarmType_SuppressedState_TrueState = 9277,
			LimitAlarmType_SuppressedState_FalseState = 9278,
			LimitAlarmType_ShelvingState = 9279,
			LimitAlarmType_ShelvingState_CurrentState = 9280,
			LimitAlarmType_ShelvingState_CurrentState_Id = 9281,
			LimitAlarmType_ShelvingState_CurrentState_Name = 9282,
			LimitAlarmType_ShelvingState_CurrentState_Number = 9283,
			LimitAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9284,
			LimitAlarmType_ShelvingState_LastTransition = 9285,
			LimitAlarmType_ShelvingState_LastTransition_Id = 9286,
			LimitAlarmType_ShelvingState_LastTransition_Name = 9287,
			LimitAlarmType_ShelvingState_LastTransition_Number = 9288,
			LimitAlarmType_ShelvingState_LastTransition_TransitionTime = 9289,
			LimitAlarmType_ShelvingState_UnshelveTime = 9290,
			LimitAlarmType_ShelvingState_Unshelve = 9312,
			LimitAlarmType_ShelvingState_OneShotShelve = 9313,
			LimitAlarmType_ShelvingState_TimedShelve = 9314,
			LimitAlarmType_ShelvingState_TimedShelve_InputArguments = 9315,
			LimitAlarmType_SuppressedOrShelved = 9316,
			LimitAlarmType_MaxTimeShelved = 9317,
			ExclusiveLimitStateMachineType = 9318,
			ExclusiveLimitStateMachineType_CurrentState = 9319,
			ExclusiveLimitStateMachineType_CurrentState_Id = 9320,
			ExclusiveLimitStateMachineType_CurrentState_Name = 9321,
			ExclusiveLimitStateMachineType_CurrentState_Number = 9322,
			ExclusiveLimitStateMachineType_CurrentState_EffectiveDisplayName = 9323,
			ExclusiveLimitStateMachineType_LastTransition = 9324,
			ExclusiveLimitStateMachineType_LastTransition_Id = 9325,
			ExclusiveLimitStateMachineType_LastTransition_Name = 9326,
			ExclusiveLimitStateMachineType_LastTransition_Number = 9327,
			ExclusiveLimitStateMachineType_LastTransition_TransitionTime = 9328,
			ExclusiveLimitStateMachineType_HighHigh = 9329,
			ExclusiveLimitStateMachineType_HighHigh_StateNumber = 9330,
			ExclusiveLimitStateMachineType_High = 9331,
			ExclusiveLimitStateMachineType_High_StateNumber = 9332,
			ExclusiveLimitStateMachineType_Low = 9333,
			ExclusiveLimitStateMachineType_Low_StateNumber = 9334,
			ExclusiveLimitStateMachineType_LowLow = 9335,
			ExclusiveLimitStateMachineType_LowLow_StateNumber = 9336,
			ExclusiveLimitStateMachineType_LowLowToLow = 9337,
			ExclusiveLimitStateMachineType_LowToLowLow = 9338,
			ExclusiveLimitStateMachineType_HighHighToHigh = 9339,
			ExclusiveLimitStateMachineType_HighToHighHigh = 9340,
			ExclusiveLimitAlarmType = 9341,
			ExclusiveLimitAlarmType_EventId = 9342,
			ExclusiveLimitAlarmType_EventType = 9343,
			ExclusiveLimitAlarmType_SourceNode = 9344,
			ExclusiveLimitAlarmType_SourceName = 9345,
			ExclusiveLimitAlarmType_Time = 9346,
			ExclusiveLimitAlarmType_ReceiveTime = 9347,
			ExclusiveLimitAlarmType_LocalTime = 9348,
			ExclusiveLimitAlarmType_Message = 9349,
			ExclusiveLimitAlarmType_Severity = 9350,
			ExclusiveLimitAlarmType_ConditionName = 9351,
			ExclusiveLimitAlarmType_BranchId = 9352,
			ExclusiveLimitAlarmType_Retain = 9353,
			ExclusiveLimitAlarmType_EnabledState = 9354,
			ExclusiveLimitAlarmType_EnabledState_Id = 9355,
			ExclusiveLimitAlarmType_EnabledState_Name = 9356,
			ExclusiveLimitAlarmType_EnabledState_Number = 9357,
			ExclusiveLimitAlarmType_EnabledState_EffectiveDisplayName = 9358,
			ExclusiveLimitAlarmType_EnabledState_TransitionTime = 9359,
			ExclusiveLimitAlarmType_EnabledState_EffectiveTransitionTime = 9360,
			ExclusiveLimitAlarmType_EnabledState_TrueState = 9361,
			ExclusiveLimitAlarmType_EnabledState_FalseState = 9362,
			ExclusiveLimitAlarmType_Quality = 9363,
			ExclusiveLimitAlarmType_Quality_SourceTimestamp = 9364,
			ExclusiveLimitAlarmType_LastSeverity = 9365,
			ExclusiveLimitAlarmType_LastSeverity_SourceTimestamp = 9366,
			ExclusiveLimitAlarmType_Comment = 9367,
			ExclusiveLimitAlarmType_Comment_SourceTimestamp = 9368,
			ExclusiveLimitAlarmType_ClientUserId = 9369,
			ExclusiveLimitAlarmType_Enable = 9370,
			ExclusiveLimitAlarmType_Disable = 9371,
			ExclusiveLimitAlarmType_AddComment = 9372,
			ExclusiveLimitAlarmType_AddComment_InputArguments = 9373,
			ExclusiveLimitAlarmType_ConditionRefresh = 9374,
			ExclusiveLimitAlarmType_ConditionRefresh_InputArguments = 9375,
			ExclusiveLimitAlarmType_AckedState = 9376,
			ExclusiveLimitAlarmType_AckedState_Id = 9377,
			ExclusiveLimitAlarmType_AckedState_Name = 9378,
			ExclusiveLimitAlarmType_AckedState_Number = 9379,
			ExclusiveLimitAlarmType_AckedState_EffectiveDisplayName = 9380,
			ExclusiveLimitAlarmType_AckedState_TransitionTime = 9381,
			ExclusiveLimitAlarmType_AckedState_EffectiveTransitionTime = 9382,
			ExclusiveLimitAlarmType_AckedState_TrueState = 9383,
			ExclusiveLimitAlarmType_AckedState_FalseState = 9384,
			ExclusiveLimitAlarmType_ConfirmedState = 9385,
			ExclusiveLimitAlarmType_ConfirmedState_Id = 9386,
			ExclusiveLimitAlarmType_ConfirmedState_Name = 9387,
			ExclusiveLimitAlarmType_ConfirmedState_Number = 9388,
			ExclusiveLimitAlarmType_ConfirmedState_EffectiveDisplayName = 9389,
			ExclusiveLimitAlarmType_ConfirmedState_TransitionTime = 9390,
			ExclusiveLimitAlarmType_ConfirmedState_EffectiveTransitionTime = 9391,
			ExclusiveLimitAlarmType_ConfirmedState_TrueState = 9392,
			ExclusiveLimitAlarmType_ConfirmedState_FalseState = 9393,
			ExclusiveLimitAlarmType_Acknowledge = 9394,
			ExclusiveLimitAlarmType_Acknowledge_InputArguments = 9395,
			ExclusiveLimitAlarmType_Confirm = 9396,
			ExclusiveLimitAlarmType_Confirm_InputArguments = 9397,
			ExclusiveLimitAlarmType_ActiveState = 9398,
			ExclusiveLimitAlarmType_ActiveState_Id = 9399,
			ExclusiveLimitAlarmType_ActiveState_Name = 9400,
			ExclusiveLimitAlarmType_ActiveState_Number = 9401,
			ExclusiveLimitAlarmType_ActiveState_EffectiveDisplayName = 9402,
			ExclusiveLimitAlarmType_ActiveState_TransitionTime = 9403,
			ExclusiveLimitAlarmType_ActiveState_EffectiveTransitionTime = 9404,
			ExclusiveLimitAlarmType_ActiveState_TrueState = 9405,
			ExclusiveLimitAlarmType_ActiveState_FalseState = 9406,
			ExclusiveLimitAlarmType_SuppressedState = 9407,
			ExclusiveLimitAlarmType_SuppressedState_Id = 9408,
			ExclusiveLimitAlarmType_SuppressedState_Name = 9409,
			ExclusiveLimitAlarmType_SuppressedState_Number = 9410,
			ExclusiveLimitAlarmType_SuppressedState_EffectiveDisplayName = 9411,
			ExclusiveLimitAlarmType_SuppressedState_TransitionTime = 9412,
			ExclusiveLimitAlarmType_SuppressedState_EffectiveTransitionTime = 9413,
			ExclusiveLimitAlarmType_SuppressedState_TrueState = 9414,
			ExclusiveLimitAlarmType_SuppressedState_FalseState = 9415,
			ExclusiveLimitAlarmType_ShelvingState = 9416,
			ExclusiveLimitAlarmType_ShelvingState_CurrentState = 9417,
			ExclusiveLimitAlarmType_ShelvingState_CurrentState_Id = 9418,
			ExclusiveLimitAlarmType_ShelvingState_CurrentState_Name = 9419,
			ExclusiveLimitAlarmType_ShelvingState_CurrentState_Number = 9420,
			ExclusiveLimitAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9421,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition = 9422,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition_Id = 9423,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition_Name = 9424,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition_Number = 9425,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition_TransitionTime = 9426,
			ExclusiveLimitAlarmType_ShelvingState_UnshelveTime = 9427,
			ExclusiveLimitAlarmType_ShelvingState_Unshelve = 9449,
			ExclusiveLimitAlarmType_ShelvingState_OneShotShelve = 9450,
			ExclusiveLimitAlarmType_ShelvingState_TimedShelve = 9451,
			ExclusiveLimitAlarmType_ShelvingState_TimedShelve_InputArguments = 9452,
			ExclusiveLimitAlarmType_SuppressedOrShelved = 9453,
			ExclusiveLimitAlarmType_MaxTimeShelved = 9454,
			ExclusiveLimitAlarmType_LimitState = 9455,
			ExclusiveLimitAlarmType_LimitState_CurrentState = 9456,
			ExclusiveLimitAlarmType_LimitState_CurrentState_Id = 9457,
			ExclusiveLimitAlarmType_LimitState_CurrentState_Name = 9458,
			ExclusiveLimitAlarmType_LimitState_CurrentState_Number = 9459,
			ExclusiveLimitAlarmType_LimitState_CurrentState_EffectiveDisplayName = 9460,
			ExclusiveLimitAlarmType_LimitState_LastTransition = 9461,
			ExclusiveLimitAlarmType_LimitState_LastTransition_Id = 9462,
			ExclusiveLimitAlarmType_LimitState_LastTransition_Name = 9463,
			ExclusiveLimitAlarmType_LimitState_LastTransition_Number = 9464,
			ExclusiveLimitAlarmType_LimitState_LastTransition_TransitionTime = 9465,
			ExclusiveLimitAlarmType_HighHighLimit = 9478,
			ExclusiveLimitAlarmType_HighLimit = 9479,
			ExclusiveLimitAlarmType_LowLimit = 9480,
			ExclusiveLimitAlarmType_LowLowLimit = 9481,
			ExclusiveLevelAlarmType = 9482,
			ExclusiveLevelAlarmType_EventId = 9483,
			ExclusiveLevelAlarmType_EventType = 9484,
			ExclusiveLevelAlarmType_SourceNode = 9485,
			ExclusiveLevelAlarmType_SourceName = 9486,
			ExclusiveLevelAlarmType_Time = 9487,
			ExclusiveLevelAlarmType_ReceiveTime = 9488,
			ExclusiveLevelAlarmType_LocalTime = 9489,
			ExclusiveLevelAlarmType_Message = 9490,
			ExclusiveLevelAlarmType_Severity = 9491,
			ExclusiveLevelAlarmType_ConditionName = 9492,
			ExclusiveLevelAlarmType_BranchId = 9493,
			ExclusiveLevelAlarmType_Retain = 9494,
			ExclusiveLevelAlarmType_EnabledState = 9495,
			ExclusiveLevelAlarmType_EnabledState_Id = 9496,
			ExclusiveLevelAlarmType_EnabledState_Name = 9497,
			ExclusiveLevelAlarmType_EnabledState_Number = 9498,
			ExclusiveLevelAlarmType_EnabledState_EffectiveDisplayName = 9499,
			ExclusiveLevelAlarmType_EnabledState_TransitionTime = 9500,
			ExclusiveLevelAlarmType_EnabledState_EffectiveTransitionTime = 9501,
			ExclusiveLevelAlarmType_EnabledState_TrueState = 9502,
			ExclusiveLevelAlarmType_EnabledState_FalseState = 9503,
			ExclusiveLevelAlarmType_Quality = 9504,
			ExclusiveLevelAlarmType_Quality_SourceTimestamp = 9505,
			ExclusiveLevelAlarmType_LastSeverity = 9506,
			ExclusiveLevelAlarmType_LastSeverity_SourceTimestamp = 9507,
			ExclusiveLevelAlarmType_Comment = 9508,
			ExclusiveLevelAlarmType_Comment_SourceTimestamp = 9509,
			ExclusiveLevelAlarmType_ClientUserId = 9510,
			ExclusiveLevelAlarmType_Enable = 9511,
			ExclusiveLevelAlarmType_Disable = 9512,
			ExclusiveLevelAlarmType_AddComment = 9513,
			ExclusiveLevelAlarmType_AddComment_InputArguments = 9514,
			ExclusiveLevelAlarmType_ConditionRefresh = 9515,
			ExclusiveLevelAlarmType_ConditionRefresh_InputArguments = 9516,
			ExclusiveLevelAlarmType_AckedState = 9517,
			ExclusiveLevelAlarmType_AckedState_Id = 9518,
			ExclusiveLevelAlarmType_AckedState_Name = 9519,
			ExclusiveLevelAlarmType_AckedState_Number = 9520,
			ExclusiveLevelAlarmType_AckedState_EffectiveDisplayName = 9521,
			ExclusiveLevelAlarmType_AckedState_TransitionTime = 9522,
			ExclusiveLevelAlarmType_AckedState_EffectiveTransitionTime = 9523,
			ExclusiveLevelAlarmType_AckedState_TrueState = 9524,
			ExclusiveLevelAlarmType_AckedState_FalseState = 9525,
			ExclusiveLevelAlarmType_ConfirmedState = 9526,
			ExclusiveLevelAlarmType_ConfirmedState_Id = 9527,
			ExclusiveLevelAlarmType_ConfirmedState_Name = 9528,
			ExclusiveLevelAlarmType_ConfirmedState_Number = 9529,
			ExclusiveLevelAlarmType_ConfirmedState_EffectiveDisplayName = 9530,
			ExclusiveLevelAlarmType_ConfirmedState_TransitionTime = 9531,
			ExclusiveLevelAlarmType_ConfirmedState_EffectiveTransitionTime = 9532,
			ExclusiveLevelAlarmType_ConfirmedState_TrueState = 9533,
			ExclusiveLevelAlarmType_ConfirmedState_FalseState = 9534,
			ExclusiveLevelAlarmType_Acknowledge = 9535,
			ExclusiveLevelAlarmType_Acknowledge_InputArguments = 9536,
			ExclusiveLevelAlarmType_Confirm = 9537,
			ExclusiveLevelAlarmType_Confirm_InputArguments = 9538,
			ExclusiveLevelAlarmType_ActiveState = 9539,
			ExclusiveLevelAlarmType_ActiveState_Id = 9540,
			ExclusiveLevelAlarmType_ActiveState_Name = 9541,
			ExclusiveLevelAlarmType_ActiveState_Number = 9542,
			ExclusiveLevelAlarmType_ActiveState_EffectiveDisplayName = 9543,
			ExclusiveLevelAlarmType_ActiveState_TransitionTime = 9544,
			ExclusiveLevelAlarmType_ActiveState_EffectiveTransitionTime = 9545,
			ExclusiveLevelAlarmType_ActiveState_TrueState = 9546,
			ExclusiveLevelAlarmType_ActiveState_FalseState = 9547,
			ExclusiveLevelAlarmType_SuppressedState = 9548,
			ExclusiveLevelAlarmType_SuppressedState_Id = 9549,
			ExclusiveLevelAlarmType_SuppressedState_Name = 9550,
			ExclusiveLevelAlarmType_SuppressedState_Number = 9551,
			ExclusiveLevelAlarmType_SuppressedState_EffectiveDisplayName = 9552,
			ExclusiveLevelAlarmType_SuppressedState_TransitionTime = 9553,
			ExclusiveLevelAlarmType_SuppressedState_EffectiveTransitionTime = 9554,
			ExclusiveLevelAlarmType_SuppressedState_TrueState = 9555,
			ExclusiveLevelAlarmType_SuppressedState_FalseState = 9556,
			ExclusiveLevelAlarmType_ShelvingState = 9557,
			ExclusiveLevelAlarmType_ShelvingState_CurrentState = 9558,
			ExclusiveLevelAlarmType_ShelvingState_CurrentState_Id = 9559,
			ExclusiveLevelAlarmType_ShelvingState_CurrentState_Name = 9560,
			ExclusiveLevelAlarmType_ShelvingState_CurrentState_Number = 9561,
			ExclusiveLevelAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9562,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition = 9563,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition_Id = 9564,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition_Name = 9565,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition_Number = 9566,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition_TransitionTime = 9567,
			ExclusiveLevelAlarmType_ShelvingState_UnshelveTime = 9568,
			ExclusiveLevelAlarmType_ShelvingState_Unshelve = 9590,
			ExclusiveLevelAlarmType_ShelvingState_OneShotShelve = 9591,
			ExclusiveLevelAlarmType_ShelvingState_TimedShelve = 9592,
			ExclusiveLevelAlarmType_ShelvingState_TimedShelve_InputArguments = 9593,
			ExclusiveLevelAlarmType_SuppressedOrShelved = 9594,
			ExclusiveLevelAlarmType_MaxTimeShelved = 9595,
			ExclusiveLevelAlarmType_LimitState = 9596,
			ExclusiveLevelAlarmType_LimitState_CurrentState = 9597,
			ExclusiveLevelAlarmType_LimitState_CurrentState_Id = 9598,
			ExclusiveLevelAlarmType_LimitState_CurrentState_Name = 9599,
			ExclusiveLevelAlarmType_LimitState_CurrentState_Number = 9600,
			ExclusiveLevelAlarmType_LimitState_CurrentState_EffectiveDisplayName = 9601,
			ExclusiveLevelAlarmType_LimitState_LastTransition = 9602,
			ExclusiveLevelAlarmType_LimitState_LastTransition_Id = 9603,
			ExclusiveLevelAlarmType_LimitState_LastTransition_Name = 9604,
			ExclusiveLevelAlarmType_LimitState_LastTransition_Number = 9605,
			ExclusiveLevelAlarmType_LimitState_LastTransition_TransitionTime = 9606,
			ExclusiveLevelAlarmType_HighHighLimit = 9619,
			ExclusiveLevelAlarmType_HighLimit = 9620,
			ExclusiveLevelAlarmType_LowLimit = 9621,
			ExclusiveLevelAlarmType_LowLowLimit = 9622,
			ExclusiveRateOfChangeAlarmType = 9623,
			ExclusiveRateOfChangeAlarmType_EventId = 9624,
			ExclusiveRateOfChangeAlarmType_EventType = 9625,
			ExclusiveRateOfChangeAlarmType_SourceNode = 9626,
			ExclusiveRateOfChangeAlarmType_SourceName = 9627,
			ExclusiveRateOfChangeAlarmType_Time = 9628,
			ExclusiveRateOfChangeAlarmType_ReceiveTime = 9629,
			ExclusiveRateOfChangeAlarmType_LocalTime = 9630,
			ExclusiveRateOfChangeAlarmType_Message = 9631,
			ExclusiveRateOfChangeAlarmType_Severity = 9632,
			ExclusiveRateOfChangeAlarmType_ConditionName = 9633,
			ExclusiveRateOfChangeAlarmType_BranchId = 9634,
			ExclusiveRateOfChangeAlarmType_Retain = 9635,
			ExclusiveRateOfChangeAlarmType_EnabledState = 9636,
			ExclusiveRateOfChangeAlarmType_EnabledState_Id = 9637,
			ExclusiveRateOfChangeAlarmType_EnabledState_Name = 9638,
			ExclusiveRateOfChangeAlarmType_EnabledState_Number = 9639,
			ExclusiveRateOfChangeAlarmType_EnabledState_EffectiveDisplayName = 9640,
			ExclusiveRateOfChangeAlarmType_EnabledState_TransitionTime = 9641,
			ExclusiveRateOfChangeAlarmType_EnabledState_EffectiveTransitionTime = 9642,
			ExclusiveRateOfChangeAlarmType_EnabledState_TrueState = 9643,
			ExclusiveRateOfChangeAlarmType_EnabledState_FalseState = 9644,
			ExclusiveRateOfChangeAlarmType_Quality = 9645,
			ExclusiveRateOfChangeAlarmType_Quality_SourceTimestamp = 9646,
			ExclusiveRateOfChangeAlarmType_LastSeverity = 9647,
			ExclusiveRateOfChangeAlarmType_LastSeverity_SourceTimestamp = 9648,
			ExclusiveRateOfChangeAlarmType_Comment = 9649,
			ExclusiveRateOfChangeAlarmType_Comment_SourceTimestamp = 9650,
			ExclusiveRateOfChangeAlarmType_ClientUserId = 9651,
			ExclusiveRateOfChangeAlarmType_Enable = 9652,
			ExclusiveRateOfChangeAlarmType_Disable = 9653,
			ExclusiveRateOfChangeAlarmType_AddComment = 9654,
			ExclusiveRateOfChangeAlarmType_AddComment_InputArguments = 9655,
			ExclusiveRateOfChangeAlarmType_ConditionRefresh = 9656,
			ExclusiveRateOfChangeAlarmType_ConditionRefresh_InputArguments = 9657,
			ExclusiveRateOfChangeAlarmType_AckedState = 9658,
			ExclusiveRateOfChangeAlarmType_AckedState_Id = 9659,
			ExclusiveRateOfChangeAlarmType_AckedState_Name = 9660,
			ExclusiveRateOfChangeAlarmType_AckedState_Number = 9661,
			ExclusiveRateOfChangeAlarmType_AckedState_EffectiveDisplayName = 9662,
			ExclusiveRateOfChangeAlarmType_AckedState_TransitionTime = 9663,
			ExclusiveRateOfChangeAlarmType_AckedState_EffectiveTransitionTime = 9664,
			ExclusiveRateOfChangeAlarmType_AckedState_TrueState = 9665,
			ExclusiveRateOfChangeAlarmType_AckedState_FalseState = 9666,
			ExclusiveRateOfChangeAlarmType_ConfirmedState = 9667,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_Id = 9668,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_Name = 9669,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_Number = 9670,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_EffectiveDisplayName = 9671,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_TransitionTime = 9672,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_EffectiveTransitionTime = 9673,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_TrueState = 9674,
			ExclusiveRateOfChangeAlarmType_ConfirmedState_FalseState = 9675,
			ExclusiveRateOfChangeAlarmType_Acknowledge = 9676,
			ExclusiveRateOfChangeAlarmType_Acknowledge_InputArguments = 9677,
			ExclusiveRateOfChangeAlarmType_Confirm = 9678,
			ExclusiveRateOfChangeAlarmType_Confirm_InputArguments = 9679,
			ExclusiveRateOfChangeAlarmType_ActiveState = 9680,
			ExclusiveRateOfChangeAlarmType_ActiveState_Id = 9681,
			ExclusiveRateOfChangeAlarmType_ActiveState_Name = 9682,
			ExclusiveRateOfChangeAlarmType_ActiveState_Number = 9683,
			ExclusiveRateOfChangeAlarmType_ActiveState_EffectiveDisplayName = 9684,
			ExclusiveRateOfChangeAlarmType_ActiveState_TransitionTime = 9685,
			ExclusiveRateOfChangeAlarmType_ActiveState_EffectiveTransitionTime = 9686,
			ExclusiveRateOfChangeAlarmType_ActiveState_TrueState = 9687,
			ExclusiveRateOfChangeAlarmType_ActiveState_FalseState = 9688,
			ExclusiveRateOfChangeAlarmType_SuppressedState = 9689,
			ExclusiveRateOfChangeAlarmType_SuppressedState_Id = 9690,
			ExclusiveRateOfChangeAlarmType_SuppressedState_Name = 9691,
			ExclusiveRateOfChangeAlarmType_SuppressedState_Number = 9692,
			ExclusiveRateOfChangeAlarmType_SuppressedState_EffectiveDisplayName = 9693,
			ExclusiveRateOfChangeAlarmType_SuppressedState_TransitionTime = 9694,
			ExclusiveRateOfChangeAlarmType_SuppressedState_EffectiveTransitionTime = 9695,
			ExclusiveRateOfChangeAlarmType_SuppressedState_TrueState = 9696,
			ExclusiveRateOfChangeAlarmType_SuppressedState_FalseState = 9697,
			ExclusiveRateOfChangeAlarmType_ShelvingState = 9698,
			ExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState = 9699,
			ExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Id = 9700,
			ExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Name = 9701,
			ExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Number = 9702,
			ExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9703,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition = 9704,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Id = 9705,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Name = 9706,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Number = 9707,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_TransitionTime = 9708,
			ExclusiveRateOfChangeAlarmType_ShelvingState_UnshelveTime = 9709,
			ExclusiveRateOfChangeAlarmType_ShelvingState_Unshelve = 9731,
			ExclusiveRateOfChangeAlarmType_ShelvingState_OneShotShelve = 9732,
			ExclusiveRateOfChangeAlarmType_ShelvingState_TimedShelve = 9733,
			ExclusiveRateOfChangeAlarmType_ShelvingState_TimedShelve_InputArguments = 9734,
			ExclusiveRateOfChangeAlarmType_SuppressedOrShelved = 9735,
			ExclusiveRateOfChangeAlarmType_MaxTimeShelved = 9736,
			ExclusiveRateOfChangeAlarmType_LimitState = 9737,
			ExclusiveRateOfChangeAlarmType_LimitState_CurrentState = 9738,
			ExclusiveRateOfChangeAlarmType_LimitState_CurrentState_Id = 9739,
			ExclusiveRateOfChangeAlarmType_LimitState_CurrentState_Name = 9740,
			ExclusiveRateOfChangeAlarmType_LimitState_CurrentState_Number = 9741,
			ExclusiveRateOfChangeAlarmType_LimitState_CurrentState_EffectiveDisplayName = 9742,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition = 9743,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_Id = 9744,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_Name = 9745,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_Number = 9746,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_TransitionTime = 9747,
			ExclusiveRateOfChangeAlarmType_HighHighLimit = 9760,
			ExclusiveRateOfChangeAlarmType_HighLimit = 9761,
			ExclusiveRateOfChangeAlarmType_LowLimit = 9762,
			ExclusiveRateOfChangeAlarmType_LowLowLimit = 9763,
			ExclusiveDeviationAlarmType = 9764,
			ExclusiveDeviationAlarmType_EventId = 9765,
			ExclusiveDeviationAlarmType_EventType = 9766,
			ExclusiveDeviationAlarmType_SourceNode = 9767,
			ExclusiveDeviationAlarmType_SourceName = 9768,
			ExclusiveDeviationAlarmType_Time = 9769,
			ExclusiveDeviationAlarmType_ReceiveTime = 9770,
			ExclusiveDeviationAlarmType_LocalTime = 9771,
			ExclusiveDeviationAlarmType_Message = 9772,
			ExclusiveDeviationAlarmType_Severity = 9773,
			ExclusiveDeviationAlarmType_ConditionName = 9774,
			ExclusiveDeviationAlarmType_BranchId = 9775,
			ExclusiveDeviationAlarmType_Retain = 9776,
			ExclusiveDeviationAlarmType_EnabledState = 9777,
			ExclusiveDeviationAlarmType_EnabledState_Id = 9778,
			ExclusiveDeviationAlarmType_EnabledState_Name = 9779,
			ExclusiveDeviationAlarmType_EnabledState_Number = 9780,
			ExclusiveDeviationAlarmType_EnabledState_EffectiveDisplayName = 9781,
			ExclusiveDeviationAlarmType_EnabledState_TransitionTime = 9782,
			ExclusiveDeviationAlarmType_EnabledState_EffectiveTransitionTime = 9783,
			ExclusiveDeviationAlarmType_EnabledState_TrueState = 9784,
			ExclusiveDeviationAlarmType_EnabledState_FalseState = 9785,
			ExclusiveDeviationAlarmType_Quality = 9786,
			ExclusiveDeviationAlarmType_Quality_SourceTimestamp = 9787,
			ExclusiveDeviationAlarmType_LastSeverity = 9788,
			ExclusiveDeviationAlarmType_LastSeverity_SourceTimestamp = 9789,
			ExclusiveDeviationAlarmType_Comment = 9790,
			ExclusiveDeviationAlarmType_Comment_SourceTimestamp = 9791,
			ExclusiveDeviationAlarmType_ClientUserId = 9792,
			ExclusiveDeviationAlarmType_Enable = 9793,
			ExclusiveDeviationAlarmType_Disable = 9794,
			ExclusiveDeviationAlarmType_AddComment = 9795,
			ExclusiveDeviationAlarmType_AddComment_InputArguments = 9796,
			ExclusiveDeviationAlarmType_ConditionRefresh = 9797,
			ExclusiveDeviationAlarmType_ConditionRefresh_InputArguments = 9798,
			ExclusiveDeviationAlarmType_AckedState = 9799,
			ExclusiveDeviationAlarmType_AckedState_Id = 9800,
			ExclusiveDeviationAlarmType_AckedState_Name = 9801,
			ExclusiveDeviationAlarmType_AckedState_Number = 9802,
			ExclusiveDeviationAlarmType_AckedState_EffectiveDisplayName = 9803,
			ExclusiveDeviationAlarmType_AckedState_TransitionTime = 9804,
			ExclusiveDeviationAlarmType_AckedState_EffectiveTransitionTime = 9805,
			ExclusiveDeviationAlarmType_AckedState_TrueState = 9806,
			ExclusiveDeviationAlarmType_AckedState_FalseState = 9807,
			ExclusiveDeviationAlarmType_ConfirmedState = 9808,
			ExclusiveDeviationAlarmType_ConfirmedState_Id = 9809,
			ExclusiveDeviationAlarmType_ConfirmedState_Name = 9810,
			ExclusiveDeviationAlarmType_ConfirmedState_Number = 9811,
			ExclusiveDeviationAlarmType_ConfirmedState_EffectiveDisplayName = 9812,
			ExclusiveDeviationAlarmType_ConfirmedState_TransitionTime = 9813,
			ExclusiveDeviationAlarmType_ConfirmedState_EffectiveTransitionTime = 9814,
			ExclusiveDeviationAlarmType_ConfirmedState_TrueState = 9815,
			ExclusiveDeviationAlarmType_ConfirmedState_FalseState = 9816,
			ExclusiveDeviationAlarmType_Acknowledge = 9817,
			ExclusiveDeviationAlarmType_Acknowledge_InputArguments = 9818,
			ExclusiveDeviationAlarmType_Confirm = 9819,
			ExclusiveDeviationAlarmType_Confirm_InputArguments = 9820,
			ExclusiveDeviationAlarmType_ActiveState = 9821,
			ExclusiveDeviationAlarmType_ActiveState_Id = 9822,
			ExclusiveDeviationAlarmType_ActiveState_Name = 9823,
			ExclusiveDeviationAlarmType_ActiveState_Number = 9824,
			ExclusiveDeviationAlarmType_ActiveState_EffectiveDisplayName = 9825,
			ExclusiveDeviationAlarmType_ActiveState_TransitionTime = 9826,
			ExclusiveDeviationAlarmType_ActiveState_EffectiveTransitionTime = 9827,
			ExclusiveDeviationAlarmType_ActiveState_TrueState = 9828,
			ExclusiveDeviationAlarmType_ActiveState_FalseState = 9829,
			ExclusiveDeviationAlarmType_SuppressedState = 9830,
			ExclusiveDeviationAlarmType_SuppressedState_Id = 9831,
			ExclusiveDeviationAlarmType_SuppressedState_Name = 9832,
			ExclusiveDeviationAlarmType_SuppressedState_Number = 9833,
			ExclusiveDeviationAlarmType_SuppressedState_EffectiveDisplayName = 9834,
			ExclusiveDeviationAlarmType_SuppressedState_TransitionTime = 9835,
			ExclusiveDeviationAlarmType_SuppressedState_EffectiveTransitionTime = 9836,
			ExclusiveDeviationAlarmType_SuppressedState_TrueState = 9837,
			ExclusiveDeviationAlarmType_SuppressedState_FalseState = 9838,
			ExclusiveDeviationAlarmType_ShelvingState = 9839,
			ExclusiveDeviationAlarmType_ShelvingState_CurrentState = 9840,
			ExclusiveDeviationAlarmType_ShelvingState_CurrentState_Id = 9841,
			ExclusiveDeviationAlarmType_ShelvingState_CurrentState_Name = 9842,
			ExclusiveDeviationAlarmType_ShelvingState_CurrentState_Number = 9843,
			ExclusiveDeviationAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9844,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition = 9845,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition_Id = 9846,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition_Name = 9847,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition_Number = 9848,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition_TransitionTime = 9849,
			ExclusiveDeviationAlarmType_ShelvingState_UnshelveTime = 9850,
			ExclusiveDeviationAlarmType_ShelvingState_Unshelve = 9872,
			ExclusiveDeviationAlarmType_ShelvingState_OneShotShelve = 9873,
			ExclusiveDeviationAlarmType_ShelvingState_TimedShelve = 9874,
			ExclusiveDeviationAlarmType_ShelvingState_TimedShelve_InputArguments = 9875,
			ExclusiveDeviationAlarmType_SuppressedOrShelved = 9876,
			ExclusiveDeviationAlarmType_MaxTimeShelved = 9877,
			ExclusiveDeviationAlarmType_LimitState = 9878,
			ExclusiveDeviationAlarmType_LimitState_CurrentState = 9879,
			ExclusiveDeviationAlarmType_LimitState_CurrentState_Id = 9880,
			ExclusiveDeviationAlarmType_LimitState_CurrentState_Name = 9881,
			ExclusiveDeviationAlarmType_LimitState_CurrentState_Number = 9882,
			ExclusiveDeviationAlarmType_LimitState_CurrentState_EffectiveDisplayName = 9883,
			ExclusiveDeviationAlarmType_LimitState_LastTransition = 9884,
			ExclusiveDeviationAlarmType_LimitState_LastTransition_Id = 9885,
			ExclusiveDeviationAlarmType_LimitState_LastTransition_Name = 9886,
			ExclusiveDeviationAlarmType_LimitState_LastTransition_Number = 9887,
			ExclusiveDeviationAlarmType_LimitState_LastTransition_TransitionTime = 9888,
			ExclusiveDeviationAlarmType_HighHighLimit = 9901,
			ExclusiveDeviationAlarmType_HighLimit = 9902,
			ExclusiveDeviationAlarmType_LowLimit = 9903,
			ExclusiveDeviationAlarmType_LowLowLimit = 9904,
			ExclusiveDeviationAlarmType_SetpointNode = 9905,
			NonExclusiveLimitAlarmType = 9906,
			NonExclusiveLimitAlarmType_EventId = 9907,
			NonExclusiveLimitAlarmType_EventType = 9908,
			NonExclusiveLimitAlarmType_SourceNode = 9909,
			NonExclusiveLimitAlarmType_SourceName = 9910,
			NonExclusiveLimitAlarmType_Time = 9911,
			NonExclusiveLimitAlarmType_ReceiveTime = 9912,
			NonExclusiveLimitAlarmType_LocalTime = 9913,
			NonExclusiveLimitAlarmType_Message = 9914,
			NonExclusiveLimitAlarmType_Severity = 9915,
			NonExclusiveLimitAlarmType_ConditionName = 9916,
			NonExclusiveLimitAlarmType_BranchId = 9917,
			NonExclusiveLimitAlarmType_Retain = 9918,
			NonExclusiveLimitAlarmType_EnabledState = 9919,
			NonExclusiveLimitAlarmType_EnabledState_Id = 9920,
			NonExclusiveLimitAlarmType_EnabledState_Name = 9921,
			NonExclusiveLimitAlarmType_EnabledState_Number = 9922,
			NonExclusiveLimitAlarmType_EnabledState_EffectiveDisplayName = 9923,
			NonExclusiveLimitAlarmType_EnabledState_TransitionTime = 9924,
			NonExclusiveLimitAlarmType_EnabledState_EffectiveTransitionTime = 9925,
			NonExclusiveLimitAlarmType_EnabledState_TrueState = 9926,
			NonExclusiveLimitAlarmType_EnabledState_FalseState = 9927,
			NonExclusiveLimitAlarmType_Quality = 9928,
			NonExclusiveLimitAlarmType_Quality_SourceTimestamp = 9929,
			NonExclusiveLimitAlarmType_LastSeverity = 9930,
			NonExclusiveLimitAlarmType_LastSeverity_SourceTimestamp = 9931,
			NonExclusiveLimitAlarmType_Comment = 9932,
			NonExclusiveLimitAlarmType_Comment_SourceTimestamp = 9933,
			NonExclusiveLimitAlarmType_ClientUserId = 9934,
			NonExclusiveLimitAlarmType_Enable = 9935,
			NonExclusiveLimitAlarmType_Disable = 9936,
			NonExclusiveLimitAlarmType_AddComment = 9937,
			NonExclusiveLimitAlarmType_AddComment_InputArguments = 9938,
			NonExclusiveLimitAlarmType_ConditionRefresh = 9939,
			NonExclusiveLimitAlarmType_ConditionRefresh_InputArguments = 9940,
			NonExclusiveLimitAlarmType_AckedState = 9941,
			NonExclusiveLimitAlarmType_AckedState_Id = 9942,
			NonExclusiveLimitAlarmType_AckedState_Name = 9943,
			NonExclusiveLimitAlarmType_AckedState_Number = 9944,
			NonExclusiveLimitAlarmType_AckedState_EffectiveDisplayName = 9945,
			NonExclusiveLimitAlarmType_AckedState_TransitionTime = 9946,
			NonExclusiveLimitAlarmType_AckedState_EffectiveTransitionTime = 9947,
			NonExclusiveLimitAlarmType_AckedState_TrueState = 9948,
			NonExclusiveLimitAlarmType_AckedState_FalseState = 9949,
			NonExclusiveLimitAlarmType_ConfirmedState = 9950,
			NonExclusiveLimitAlarmType_ConfirmedState_Id = 9951,
			NonExclusiveLimitAlarmType_ConfirmedState_Name = 9952,
			NonExclusiveLimitAlarmType_ConfirmedState_Number = 9953,
			NonExclusiveLimitAlarmType_ConfirmedState_EffectiveDisplayName = 9954,
			NonExclusiveLimitAlarmType_ConfirmedState_TransitionTime = 9955,
			NonExclusiveLimitAlarmType_ConfirmedState_EffectiveTransitionTime = 9956,
			NonExclusiveLimitAlarmType_ConfirmedState_TrueState = 9957,
			NonExclusiveLimitAlarmType_ConfirmedState_FalseState = 9958,
			NonExclusiveLimitAlarmType_Acknowledge = 9959,
			NonExclusiveLimitAlarmType_Acknowledge_InputArguments = 9960,
			NonExclusiveLimitAlarmType_Confirm = 9961,
			NonExclusiveLimitAlarmType_Confirm_InputArguments = 9962,
			NonExclusiveLimitAlarmType_ActiveState = 9963,
			NonExclusiveLimitAlarmType_ActiveState_Id = 9964,
			NonExclusiveLimitAlarmType_ActiveState_Name = 9965,
			NonExclusiveLimitAlarmType_ActiveState_Number = 9966,
			NonExclusiveLimitAlarmType_ActiveState_EffectiveDisplayName = 9967,
			NonExclusiveLimitAlarmType_ActiveState_TransitionTime = 9968,
			NonExclusiveLimitAlarmType_ActiveState_EffectiveTransitionTime = 9969,
			NonExclusiveLimitAlarmType_ActiveState_TrueState = 9970,
			NonExclusiveLimitAlarmType_ActiveState_FalseState = 9971,
			NonExclusiveLimitAlarmType_SuppressedState = 9972,
			NonExclusiveLimitAlarmType_SuppressedState_Id = 9973,
			NonExclusiveLimitAlarmType_SuppressedState_Name = 9974,
			NonExclusiveLimitAlarmType_SuppressedState_Number = 9975,
			NonExclusiveLimitAlarmType_SuppressedState_EffectiveDisplayName = 9976,
			NonExclusiveLimitAlarmType_SuppressedState_TransitionTime = 9977,
			NonExclusiveLimitAlarmType_SuppressedState_EffectiveTransitionTime = 9978,
			NonExclusiveLimitAlarmType_SuppressedState_TrueState = 9979,
			NonExclusiveLimitAlarmType_SuppressedState_FalseState = 9980,
			NonExclusiveLimitAlarmType_ShelvingState = 9981,
			NonExclusiveLimitAlarmType_ShelvingState_CurrentState = 9982,
			NonExclusiveLimitAlarmType_ShelvingState_CurrentState_Id = 9983,
			NonExclusiveLimitAlarmType_ShelvingState_CurrentState_Name = 9984,
			NonExclusiveLimitAlarmType_ShelvingState_CurrentState_Number = 9985,
			NonExclusiveLimitAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 9986,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition = 9987,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition_Id = 9988,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition_Name = 9989,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition_Number = 9990,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition_TransitionTime = 9991,
			NonExclusiveLimitAlarmType_ShelvingState_UnshelveTime = 9992,
			NonExclusiveLimitAlarmType_ShelvingState_Unshelve = 10014,
			NonExclusiveLimitAlarmType_ShelvingState_OneShotShelve = 10015,
			NonExclusiveLimitAlarmType_ShelvingState_TimedShelve = 10016,
			NonExclusiveLimitAlarmType_ShelvingState_TimedShelve_InputArguments = 10017,
			NonExclusiveLimitAlarmType_SuppressedOrShelved = 10018,
			NonExclusiveLimitAlarmType_MaxTimeShelved = 10019,
			NonExclusiveLimitAlarmType_HighHighState = 10020,
			NonExclusiveLimitAlarmType_HighHighState_Id = 10021,
			NonExclusiveLimitAlarmType_HighHighState_Name = 10022,
			NonExclusiveLimitAlarmType_HighHighState_Number = 10023,
			NonExclusiveLimitAlarmType_HighHighState_EffectiveDisplayName = 10024,
			NonExclusiveLimitAlarmType_HighHighState_TransitionTime = 10025,
			NonExclusiveLimitAlarmType_HighHighState_EffectiveTransitionTime = 10026,
			NonExclusiveLimitAlarmType_HighHighState_TrueState = 10027,
			NonExclusiveLimitAlarmType_HighHighState_FalseState = 10028,
			NonExclusiveLimitAlarmType_HighState = 10029,
			NonExclusiveLimitAlarmType_HighState_Id = 10030,
			NonExclusiveLimitAlarmType_HighState_Name = 10031,
			NonExclusiveLimitAlarmType_HighState_Number = 10032,
			NonExclusiveLimitAlarmType_HighState_EffectiveDisplayName = 10033,
			NonExclusiveLimitAlarmType_HighState_TransitionTime = 10034,
			NonExclusiveLimitAlarmType_HighState_EffectiveTransitionTime = 10035,
			NonExclusiveLimitAlarmType_HighState_TrueState = 10036,
			NonExclusiveLimitAlarmType_HighState_FalseState = 10037,
			NonExclusiveLimitAlarmType_LowState = 10038,
			NonExclusiveLimitAlarmType_LowState_Id = 10039,
			NonExclusiveLimitAlarmType_LowState_Name = 10040,
			NonExclusiveLimitAlarmType_LowState_Number = 10041,
			NonExclusiveLimitAlarmType_LowState_EffectiveDisplayName = 10042,
			NonExclusiveLimitAlarmType_LowState_TransitionTime = 10043,
			NonExclusiveLimitAlarmType_LowState_EffectiveTransitionTime = 10044,
			NonExclusiveLimitAlarmType_LowState_TrueState = 10045,
			NonExclusiveLimitAlarmType_LowState_FalseState = 10046,
			NonExclusiveLimitAlarmType_LowLowState = 10047,
			NonExclusiveLimitAlarmType_LowLowState_Id = 10048,
			NonExclusiveLimitAlarmType_LowLowState_Name = 10049,
			NonExclusiveLimitAlarmType_LowLowState_Number = 10050,
			NonExclusiveLimitAlarmType_LowLowState_EffectiveDisplayName = 10051,
			NonExclusiveLimitAlarmType_LowLowState_TransitionTime = 10052,
			NonExclusiveLimitAlarmType_LowLowState_EffectiveTransitionTime = 10053,
			NonExclusiveLimitAlarmType_LowLowState_TrueState = 10054,
			NonExclusiveLimitAlarmType_LowLowState_FalseState = 10055,
			NonExclusiveLimitAlarmType_HighHighLimit = 10056,
			NonExclusiveLimitAlarmType_HighLimit = 10057,
			NonExclusiveLimitAlarmType_LowLimit = 10058,
			NonExclusiveLimitAlarmType_LowLowLimit = 10059,
			NonExclusiveLevelAlarmType = 10060,
			NonExclusiveLevelAlarmType_EventId = 10061,
			NonExclusiveLevelAlarmType_EventType = 10062,
			NonExclusiveLevelAlarmType_SourceNode = 10063,
			NonExclusiveLevelAlarmType_SourceName = 10064,
			NonExclusiveLevelAlarmType_Time = 10065,
			NonExclusiveLevelAlarmType_ReceiveTime = 10066,
			NonExclusiveLevelAlarmType_LocalTime = 10067,
			NonExclusiveLevelAlarmType_Message = 10068,
			NonExclusiveLevelAlarmType_Severity = 10069,
			NonExclusiveLevelAlarmType_ConditionName = 10070,
			NonExclusiveLevelAlarmType_BranchId = 10071,
			NonExclusiveLevelAlarmType_Retain = 10072,
			NonExclusiveLevelAlarmType_EnabledState = 10073,
			NonExclusiveLevelAlarmType_EnabledState_Id = 10074,
			NonExclusiveLevelAlarmType_EnabledState_Name = 10075,
			NonExclusiveLevelAlarmType_EnabledState_Number = 10076,
			NonExclusiveLevelAlarmType_EnabledState_EffectiveDisplayName = 10077,
			NonExclusiveLevelAlarmType_EnabledState_TransitionTime = 10078,
			NonExclusiveLevelAlarmType_EnabledState_EffectiveTransitionTime = 10079,
			NonExclusiveLevelAlarmType_EnabledState_TrueState = 10080,
			NonExclusiveLevelAlarmType_EnabledState_FalseState = 10081,
			NonExclusiveLevelAlarmType_Quality = 10082,
			NonExclusiveLevelAlarmType_Quality_SourceTimestamp = 10083,
			NonExclusiveLevelAlarmType_LastSeverity = 10084,
			NonExclusiveLevelAlarmType_LastSeverity_SourceTimestamp = 10085,
			NonExclusiveLevelAlarmType_Comment = 10086,
			NonExclusiveLevelAlarmType_Comment_SourceTimestamp = 10087,
			NonExclusiveLevelAlarmType_ClientUserId = 10088,
			NonExclusiveLevelAlarmType_Enable = 10089,
			NonExclusiveLevelAlarmType_Disable = 10090,
			NonExclusiveLevelAlarmType_AddComment = 10091,
			NonExclusiveLevelAlarmType_AddComment_InputArguments = 10092,
			NonExclusiveLevelAlarmType_ConditionRefresh = 10093,
			NonExclusiveLevelAlarmType_ConditionRefresh_InputArguments = 10094,
			NonExclusiveLevelAlarmType_AckedState = 10095,
			NonExclusiveLevelAlarmType_AckedState_Id = 10096,
			NonExclusiveLevelAlarmType_AckedState_Name = 10097,
			NonExclusiveLevelAlarmType_AckedState_Number = 10098,
			NonExclusiveLevelAlarmType_AckedState_EffectiveDisplayName = 10099,
			NonExclusiveLevelAlarmType_AckedState_TransitionTime = 10100,
			NonExclusiveLevelAlarmType_AckedState_EffectiveTransitionTime = 10101,
			NonExclusiveLevelAlarmType_AckedState_TrueState = 10102,
			NonExclusiveLevelAlarmType_AckedState_FalseState = 10103,
			NonExclusiveLevelAlarmType_ConfirmedState = 10104,
			NonExclusiveLevelAlarmType_ConfirmedState_Id = 10105,
			NonExclusiveLevelAlarmType_ConfirmedState_Name = 10106,
			NonExclusiveLevelAlarmType_ConfirmedState_Number = 10107,
			NonExclusiveLevelAlarmType_ConfirmedState_EffectiveDisplayName = 10108,
			NonExclusiveLevelAlarmType_ConfirmedState_TransitionTime = 10109,
			NonExclusiveLevelAlarmType_ConfirmedState_EffectiveTransitionTime = 10110,
			NonExclusiveLevelAlarmType_ConfirmedState_TrueState = 10111,
			NonExclusiveLevelAlarmType_ConfirmedState_FalseState = 10112,
			NonExclusiveLevelAlarmType_Acknowledge = 10113,
			NonExclusiveLevelAlarmType_Acknowledge_InputArguments = 10114,
			NonExclusiveLevelAlarmType_Confirm = 10115,
			NonExclusiveLevelAlarmType_Confirm_InputArguments = 10116,
			NonExclusiveLevelAlarmType_ActiveState = 10117,
			NonExclusiveLevelAlarmType_ActiveState_Id = 10118,
			NonExclusiveLevelAlarmType_ActiveState_Name = 10119,
			NonExclusiveLevelAlarmType_ActiveState_Number = 10120,
			NonExclusiveLevelAlarmType_ActiveState_EffectiveDisplayName = 10121,
			NonExclusiveLevelAlarmType_ActiveState_TransitionTime = 10122,
			NonExclusiveLevelAlarmType_ActiveState_EffectiveTransitionTime = 10123,
			NonExclusiveLevelAlarmType_ActiveState_TrueState = 10124,
			NonExclusiveLevelAlarmType_ActiveState_FalseState = 10125,
			NonExclusiveLevelAlarmType_SuppressedState = 10126,
			NonExclusiveLevelAlarmType_SuppressedState_Id = 10127,
			NonExclusiveLevelAlarmType_SuppressedState_Name = 10128,
			NonExclusiveLevelAlarmType_SuppressedState_Number = 10129,
			NonExclusiveLevelAlarmType_SuppressedState_EffectiveDisplayName = 10130,
			NonExclusiveLevelAlarmType_SuppressedState_TransitionTime = 10131,
			NonExclusiveLevelAlarmType_SuppressedState_EffectiveTransitionTime = 10132,
			NonExclusiveLevelAlarmType_SuppressedState_TrueState = 10133,
			NonExclusiveLevelAlarmType_SuppressedState_FalseState = 10134,
			NonExclusiveLevelAlarmType_ShelvingState = 10135,
			NonExclusiveLevelAlarmType_ShelvingState_CurrentState = 10136,
			NonExclusiveLevelAlarmType_ShelvingState_CurrentState_Id = 10137,
			NonExclusiveLevelAlarmType_ShelvingState_CurrentState_Name = 10138,
			NonExclusiveLevelAlarmType_ShelvingState_CurrentState_Number = 10139,
			NonExclusiveLevelAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10140,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition = 10141,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition_Id = 10142,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition_Name = 10143,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition_Number = 10144,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition_TransitionTime = 10145,
			NonExclusiveLevelAlarmType_ShelvingState_UnshelveTime = 10146,
			NonExclusiveLevelAlarmType_ShelvingState_Unshelve = 10168,
			NonExclusiveLevelAlarmType_ShelvingState_OneShotShelve = 10169,
			NonExclusiveLevelAlarmType_ShelvingState_TimedShelve = 10170,
			NonExclusiveLevelAlarmType_ShelvingState_TimedShelve_InputArguments = 10171,
			NonExclusiveLevelAlarmType_SuppressedOrShelved = 10172,
			NonExclusiveLevelAlarmType_MaxTimeShelved = 10173,
			NonExclusiveLevelAlarmType_HighHighState = 10174,
			NonExclusiveLevelAlarmType_HighHighState_Id = 10175,
			NonExclusiveLevelAlarmType_HighHighState_Name = 10176,
			NonExclusiveLevelAlarmType_HighHighState_Number = 10177,
			NonExclusiveLevelAlarmType_HighHighState_EffectiveDisplayName = 10178,
			NonExclusiveLevelAlarmType_HighHighState_TransitionTime = 10179,
			NonExclusiveLevelAlarmType_HighHighState_EffectiveTransitionTime = 10180,
			NonExclusiveLevelAlarmType_HighHighState_TrueState = 10181,
			NonExclusiveLevelAlarmType_HighHighState_FalseState = 10182,
			NonExclusiveLevelAlarmType_HighState = 10183,
			NonExclusiveLevelAlarmType_HighState_Id = 10184,
			NonExclusiveLevelAlarmType_HighState_Name = 10185,
			NonExclusiveLevelAlarmType_HighState_Number = 10186,
			NonExclusiveLevelAlarmType_HighState_EffectiveDisplayName = 10187,
			NonExclusiveLevelAlarmType_HighState_TransitionTime = 10188,
			NonExclusiveLevelAlarmType_HighState_EffectiveTransitionTime = 10189,
			NonExclusiveLevelAlarmType_HighState_TrueState = 10190,
			NonExclusiveLevelAlarmType_HighState_FalseState = 10191,
			NonExclusiveLevelAlarmType_LowState = 10192,
			NonExclusiveLevelAlarmType_LowState_Id = 10193,
			NonExclusiveLevelAlarmType_LowState_Name = 10194,
			NonExclusiveLevelAlarmType_LowState_Number = 10195,
			NonExclusiveLevelAlarmType_LowState_EffectiveDisplayName = 10196,
			NonExclusiveLevelAlarmType_LowState_TransitionTime = 10197,
			NonExclusiveLevelAlarmType_LowState_EffectiveTransitionTime = 10198,
			NonExclusiveLevelAlarmType_LowState_TrueState = 10199,
			NonExclusiveLevelAlarmType_LowState_FalseState = 10200,
			NonExclusiveLevelAlarmType_LowLowState = 10201,
			NonExclusiveLevelAlarmType_LowLowState_Id = 10202,
			NonExclusiveLevelAlarmType_LowLowState_Name = 10203,
			NonExclusiveLevelAlarmType_LowLowState_Number = 10204,
			NonExclusiveLevelAlarmType_LowLowState_EffectiveDisplayName = 10205,
			NonExclusiveLevelAlarmType_LowLowState_TransitionTime = 10206,
			NonExclusiveLevelAlarmType_LowLowState_EffectiveTransitionTime = 10207,
			NonExclusiveLevelAlarmType_LowLowState_TrueState = 10208,
			NonExclusiveLevelAlarmType_LowLowState_FalseState = 10209,
			NonExclusiveLevelAlarmType_HighHighLimit = 10210,
			NonExclusiveLevelAlarmType_HighLimit = 10211,
			NonExclusiveLevelAlarmType_LowLimit = 10212,
			NonExclusiveLevelAlarmType_LowLowLimit = 10213,
			NonExclusiveRateOfChangeAlarmType = 10214,
			NonExclusiveRateOfChangeAlarmType_EventId = 10215,
			NonExclusiveRateOfChangeAlarmType_EventType = 10216,
			NonExclusiveRateOfChangeAlarmType_SourceNode = 10217,
			NonExclusiveRateOfChangeAlarmType_SourceName = 10218,
			NonExclusiveRateOfChangeAlarmType_Time = 10219,
			NonExclusiveRateOfChangeAlarmType_ReceiveTime = 10220,
			NonExclusiveRateOfChangeAlarmType_LocalTime = 10221,
			NonExclusiveRateOfChangeAlarmType_Message = 10222,
			NonExclusiveRateOfChangeAlarmType_Severity = 10223,
			NonExclusiveRateOfChangeAlarmType_ConditionName = 10224,
			NonExclusiveRateOfChangeAlarmType_BranchId = 10225,
			NonExclusiveRateOfChangeAlarmType_Retain = 10226,
			NonExclusiveRateOfChangeAlarmType_EnabledState = 10227,
			NonExclusiveRateOfChangeAlarmType_EnabledState_Id = 10228,
			NonExclusiveRateOfChangeAlarmType_EnabledState_Name = 10229,
			NonExclusiveRateOfChangeAlarmType_EnabledState_Number = 10230,
			NonExclusiveRateOfChangeAlarmType_EnabledState_EffectiveDisplayName = 10231,
			NonExclusiveRateOfChangeAlarmType_EnabledState_TransitionTime = 10232,
			NonExclusiveRateOfChangeAlarmType_EnabledState_EffectiveTransitionTime = 10233,
			NonExclusiveRateOfChangeAlarmType_EnabledState_TrueState = 10234,
			NonExclusiveRateOfChangeAlarmType_EnabledState_FalseState = 10235,
			NonExclusiveRateOfChangeAlarmType_Quality = 10236,
			NonExclusiveRateOfChangeAlarmType_Quality_SourceTimestamp = 10237,
			NonExclusiveRateOfChangeAlarmType_LastSeverity = 10238,
			NonExclusiveRateOfChangeAlarmType_LastSeverity_SourceTimestamp = 10239,
			NonExclusiveRateOfChangeAlarmType_Comment = 10240,
			NonExclusiveRateOfChangeAlarmType_Comment_SourceTimestamp = 10241,
			NonExclusiveRateOfChangeAlarmType_ClientUserId = 10242,
			NonExclusiveRateOfChangeAlarmType_Enable = 10243,
			NonExclusiveRateOfChangeAlarmType_Disable = 10244,
			NonExclusiveRateOfChangeAlarmType_AddComment = 10245,
			NonExclusiveRateOfChangeAlarmType_AddComment_InputArguments = 10246,
			NonExclusiveRateOfChangeAlarmType_ConditionRefresh = 10247,
			NonExclusiveRateOfChangeAlarmType_ConditionRefresh_InputArguments = 10248,
			NonExclusiveRateOfChangeAlarmType_AckedState = 10249,
			NonExclusiveRateOfChangeAlarmType_AckedState_Id = 10250,
			NonExclusiveRateOfChangeAlarmType_AckedState_Name = 10251,
			NonExclusiveRateOfChangeAlarmType_AckedState_Number = 10252,
			NonExclusiveRateOfChangeAlarmType_AckedState_EffectiveDisplayName = 10253,
			NonExclusiveRateOfChangeAlarmType_AckedState_TransitionTime = 10254,
			NonExclusiveRateOfChangeAlarmType_AckedState_EffectiveTransitionTime = 10255,
			NonExclusiveRateOfChangeAlarmType_AckedState_TrueState = 10256,
			NonExclusiveRateOfChangeAlarmType_AckedState_FalseState = 10257,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState = 10258,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_Id = 10259,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_Name = 10260,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_Number = 10261,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_EffectiveDisplayName = 10262,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_TransitionTime = 10263,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_EffectiveTransitionTime = 10264,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_TrueState = 10265,
			NonExclusiveRateOfChangeAlarmType_ConfirmedState_FalseState = 10266,
			NonExclusiveRateOfChangeAlarmType_Acknowledge = 10267,
			NonExclusiveRateOfChangeAlarmType_Acknowledge_InputArguments = 10268,
			NonExclusiveRateOfChangeAlarmType_Confirm = 10269,
			NonExclusiveRateOfChangeAlarmType_Confirm_InputArguments = 10270,
			NonExclusiveRateOfChangeAlarmType_ActiveState = 10271,
			NonExclusiveRateOfChangeAlarmType_ActiveState_Id = 10272,
			NonExclusiveRateOfChangeAlarmType_ActiveState_Name = 10273,
			NonExclusiveRateOfChangeAlarmType_ActiveState_Number = 10274,
			NonExclusiveRateOfChangeAlarmType_ActiveState_EffectiveDisplayName = 10275,
			NonExclusiveRateOfChangeAlarmType_ActiveState_TransitionTime = 10276,
			NonExclusiveRateOfChangeAlarmType_ActiveState_EffectiveTransitionTime = 10277,
			NonExclusiveRateOfChangeAlarmType_ActiveState_TrueState = 10278,
			NonExclusiveRateOfChangeAlarmType_ActiveState_FalseState = 10279,
			NonExclusiveRateOfChangeAlarmType_SuppressedState = 10280,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_Id = 10281,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_Name = 10282,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_Number = 10283,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_EffectiveDisplayName = 10284,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_TransitionTime = 10285,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_EffectiveTransitionTime = 10286,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_TrueState = 10287,
			NonExclusiveRateOfChangeAlarmType_SuppressedState_FalseState = 10288,
			NonExclusiveRateOfChangeAlarmType_ShelvingState = 10289,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState = 10290,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Id = 10291,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Name = 10292,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_Number = 10293,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10294,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition = 10295,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Id = 10296,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Name = 10297,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_Number = 10298,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_TransitionTime = 10299,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_UnshelveTime = 10300,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_Unshelve = 10322,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_OneShotShelve = 10323,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_TimedShelve = 10324,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_TimedShelve_InputArguments = 10325,
			NonExclusiveRateOfChangeAlarmType_SuppressedOrShelved = 10326,
			NonExclusiveRateOfChangeAlarmType_MaxTimeShelved = 10327,
			NonExclusiveRateOfChangeAlarmType_HighHighState = 10328,
			NonExclusiveRateOfChangeAlarmType_HighHighState_Id = 10329,
			NonExclusiveRateOfChangeAlarmType_HighHighState_Name = 10330,
			NonExclusiveRateOfChangeAlarmType_HighHighState_Number = 10331,
			NonExclusiveRateOfChangeAlarmType_HighHighState_EffectiveDisplayName = 10332,
			NonExclusiveRateOfChangeAlarmType_HighHighState_TransitionTime = 10333,
			NonExclusiveRateOfChangeAlarmType_HighHighState_EffectiveTransitionTime = 10334,
			NonExclusiveRateOfChangeAlarmType_HighHighState_TrueState = 10335,
			NonExclusiveRateOfChangeAlarmType_HighHighState_FalseState = 10336,
			NonExclusiveRateOfChangeAlarmType_HighState = 10337,
			NonExclusiveRateOfChangeAlarmType_HighState_Id = 10338,
			NonExclusiveRateOfChangeAlarmType_HighState_Name = 10339,
			NonExclusiveRateOfChangeAlarmType_HighState_Number = 10340,
			NonExclusiveRateOfChangeAlarmType_HighState_EffectiveDisplayName = 10341,
			NonExclusiveRateOfChangeAlarmType_HighState_TransitionTime = 10342,
			NonExclusiveRateOfChangeAlarmType_HighState_EffectiveTransitionTime = 10343,
			NonExclusiveRateOfChangeAlarmType_HighState_TrueState = 10344,
			NonExclusiveRateOfChangeAlarmType_HighState_FalseState = 10345,
			NonExclusiveRateOfChangeAlarmType_LowState = 10346,
			NonExclusiveRateOfChangeAlarmType_LowState_Id = 10347,
			NonExclusiveRateOfChangeAlarmType_LowState_Name = 10348,
			NonExclusiveRateOfChangeAlarmType_LowState_Number = 10349,
			NonExclusiveRateOfChangeAlarmType_LowState_EffectiveDisplayName = 10350,
			NonExclusiveRateOfChangeAlarmType_LowState_TransitionTime = 10351,
			NonExclusiveRateOfChangeAlarmType_LowState_EffectiveTransitionTime = 10352,
			NonExclusiveRateOfChangeAlarmType_LowState_TrueState = 10353,
			NonExclusiveRateOfChangeAlarmType_LowState_FalseState = 10354,
			NonExclusiveRateOfChangeAlarmType_LowLowState = 10355,
			NonExclusiveRateOfChangeAlarmType_LowLowState_Id = 10356,
			NonExclusiveRateOfChangeAlarmType_LowLowState_Name = 10357,
			NonExclusiveRateOfChangeAlarmType_LowLowState_Number = 10358,
			NonExclusiveRateOfChangeAlarmType_LowLowState_EffectiveDisplayName = 10359,
			NonExclusiveRateOfChangeAlarmType_LowLowState_TransitionTime = 10360,
			NonExclusiveRateOfChangeAlarmType_LowLowState_EffectiveTransitionTime = 10361,
			NonExclusiveRateOfChangeAlarmType_LowLowState_TrueState = 10362,
			NonExclusiveRateOfChangeAlarmType_LowLowState_FalseState = 10363,
			NonExclusiveRateOfChangeAlarmType_HighHighLimit = 10364,
			NonExclusiveRateOfChangeAlarmType_HighLimit = 10365,
			NonExclusiveRateOfChangeAlarmType_LowLimit = 10366,
			NonExclusiveRateOfChangeAlarmType_LowLowLimit = 10367,
			NonExclusiveDeviationAlarmType = 10368,
			NonExclusiveDeviationAlarmType_EventId = 10369,
			NonExclusiveDeviationAlarmType_EventType = 10370,
			NonExclusiveDeviationAlarmType_SourceNode = 10371,
			NonExclusiveDeviationAlarmType_SourceName = 10372,
			NonExclusiveDeviationAlarmType_Time = 10373,
			NonExclusiveDeviationAlarmType_ReceiveTime = 10374,
			NonExclusiveDeviationAlarmType_LocalTime = 10375,
			NonExclusiveDeviationAlarmType_Message = 10376,
			NonExclusiveDeviationAlarmType_Severity = 10377,
			NonExclusiveDeviationAlarmType_ConditionName = 10378,
			NonExclusiveDeviationAlarmType_BranchId = 10379,
			NonExclusiveDeviationAlarmType_Retain = 10380,
			NonExclusiveDeviationAlarmType_EnabledState = 10381,
			NonExclusiveDeviationAlarmType_EnabledState_Id = 10382,
			NonExclusiveDeviationAlarmType_EnabledState_Name = 10383,
			NonExclusiveDeviationAlarmType_EnabledState_Number = 10384,
			NonExclusiveDeviationAlarmType_EnabledState_EffectiveDisplayName = 10385,
			NonExclusiveDeviationAlarmType_EnabledState_TransitionTime = 10386,
			NonExclusiveDeviationAlarmType_EnabledState_EffectiveTransitionTime = 10387,
			NonExclusiveDeviationAlarmType_EnabledState_TrueState = 10388,
			NonExclusiveDeviationAlarmType_EnabledState_FalseState = 10389,
			NonExclusiveDeviationAlarmType_Quality = 10390,
			NonExclusiveDeviationAlarmType_Quality_SourceTimestamp = 10391,
			NonExclusiveDeviationAlarmType_LastSeverity = 10392,
			NonExclusiveDeviationAlarmType_LastSeverity_SourceTimestamp = 10393,
			NonExclusiveDeviationAlarmType_Comment = 10394,
			NonExclusiveDeviationAlarmType_Comment_SourceTimestamp = 10395,
			NonExclusiveDeviationAlarmType_ClientUserId = 10396,
			NonExclusiveDeviationAlarmType_Enable = 10397,
			NonExclusiveDeviationAlarmType_Disable = 10398,
			NonExclusiveDeviationAlarmType_AddComment = 10399,
			NonExclusiveDeviationAlarmType_AddComment_InputArguments = 10400,
			NonExclusiveDeviationAlarmType_ConditionRefresh = 10401,
			NonExclusiveDeviationAlarmType_ConditionRefresh_InputArguments = 10402,
			NonExclusiveDeviationAlarmType_AckedState = 10403,
			NonExclusiveDeviationAlarmType_AckedState_Id = 10404,
			NonExclusiveDeviationAlarmType_AckedState_Name = 10405,
			NonExclusiveDeviationAlarmType_AckedState_Number = 10406,
			NonExclusiveDeviationAlarmType_AckedState_EffectiveDisplayName = 10407,
			NonExclusiveDeviationAlarmType_AckedState_TransitionTime = 10408,
			NonExclusiveDeviationAlarmType_AckedState_EffectiveTransitionTime = 10409,
			NonExclusiveDeviationAlarmType_AckedState_TrueState = 10410,
			NonExclusiveDeviationAlarmType_AckedState_FalseState = 10411,
			NonExclusiveDeviationAlarmType_ConfirmedState = 10412,
			NonExclusiveDeviationAlarmType_ConfirmedState_Id = 10413,
			NonExclusiveDeviationAlarmType_ConfirmedState_Name = 10414,
			NonExclusiveDeviationAlarmType_ConfirmedState_Number = 10415,
			NonExclusiveDeviationAlarmType_ConfirmedState_EffectiveDisplayName = 10416,
			NonExclusiveDeviationAlarmType_ConfirmedState_TransitionTime = 10417,
			NonExclusiveDeviationAlarmType_ConfirmedState_EffectiveTransitionTime = 10418,
			NonExclusiveDeviationAlarmType_ConfirmedState_TrueState = 10419,
			NonExclusiveDeviationAlarmType_ConfirmedState_FalseState = 10420,
			NonExclusiveDeviationAlarmType_Acknowledge = 10421,
			NonExclusiveDeviationAlarmType_Acknowledge_InputArguments = 10422,
			NonExclusiveDeviationAlarmType_Confirm = 10423,
			NonExclusiveDeviationAlarmType_Confirm_InputArguments = 10424,
			NonExclusiveDeviationAlarmType_ActiveState = 10425,
			NonExclusiveDeviationAlarmType_ActiveState_Id = 10426,
			NonExclusiveDeviationAlarmType_ActiveState_Name = 10427,
			NonExclusiveDeviationAlarmType_ActiveState_Number = 10428,
			NonExclusiveDeviationAlarmType_ActiveState_EffectiveDisplayName = 10429,
			NonExclusiveDeviationAlarmType_ActiveState_TransitionTime = 10430,
			NonExclusiveDeviationAlarmType_ActiveState_EffectiveTransitionTime = 10431,
			NonExclusiveDeviationAlarmType_ActiveState_TrueState = 10432,
			NonExclusiveDeviationAlarmType_ActiveState_FalseState = 10433,
			NonExclusiveDeviationAlarmType_SuppressedState = 10434,
			NonExclusiveDeviationAlarmType_SuppressedState_Id = 10435,
			NonExclusiveDeviationAlarmType_SuppressedState_Name = 10436,
			NonExclusiveDeviationAlarmType_SuppressedState_Number = 10437,
			NonExclusiveDeviationAlarmType_SuppressedState_EffectiveDisplayName = 10438,
			NonExclusiveDeviationAlarmType_SuppressedState_TransitionTime = 10439,
			NonExclusiveDeviationAlarmType_SuppressedState_EffectiveTransitionTime = 10440,
			NonExclusiveDeviationAlarmType_SuppressedState_TrueState = 10441,
			NonExclusiveDeviationAlarmType_SuppressedState_FalseState = 10442,
			NonExclusiveDeviationAlarmType_ShelvingState = 10443,
			NonExclusiveDeviationAlarmType_ShelvingState_CurrentState = 10444,
			NonExclusiveDeviationAlarmType_ShelvingState_CurrentState_Id = 10445,
			NonExclusiveDeviationAlarmType_ShelvingState_CurrentState_Name = 10446,
			NonExclusiveDeviationAlarmType_ShelvingState_CurrentState_Number = 10447,
			NonExclusiveDeviationAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10448,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition = 10449,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition_Id = 10450,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition_Name = 10451,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition_Number = 10452,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition_TransitionTime = 10453,
			NonExclusiveDeviationAlarmType_ShelvingState_UnshelveTime = 10454,
			NonExclusiveDeviationAlarmType_ShelvingState_Unshelve = 10476,
			NonExclusiveDeviationAlarmType_ShelvingState_OneShotShelve = 10477,
			NonExclusiveDeviationAlarmType_ShelvingState_TimedShelve = 10478,
			NonExclusiveDeviationAlarmType_ShelvingState_TimedShelve_InputArguments = 10479,
			NonExclusiveDeviationAlarmType_SuppressedOrShelved = 10480,
			NonExclusiveDeviationAlarmType_MaxTimeShelved = 10481,
			NonExclusiveDeviationAlarmType_HighHighState = 10482,
			NonExclusiveDeviationAlarmType_HighHighState_Id = 10483,
			NonExclusiveDeviationAlarmType_HighHighState_Name = 10484,
			NonExclusiveDeviationAlarmType_HighHighState_Number = 10485,
			NonExclusiveDeviationAlarmType_HighHighState_EffectiveDisplayName = 10486,
			NonExclusiveDeviationAlarmType_HighHighState_TransitionTime = 10487,
			NonExclusiveDeviationAlarmType_HighHighState_EffectiveTransitionTime = 10488,
			NonExclusiveDeviationAlarmType_HighHighState_TrueState = 10489,
			NonExclusiveDeviationAlarmType_HighHighState_FalseState = 10490,
			NonExclusiveDeviationAlarmType_HighState = 10491,
			NonExclusiveDeviationAlarmType_HighState_Id = 10492,
			NonExclusiveDeviationAlarmType_HighState_Name = 10493,
			NonExclusiveDeviationAlarmType_HighState_Number = 10494,
			NonExclusiveDeviationAlarmType_HighState_EffectiveDisplayName = 10495,
			NonExclusiveDeviationAlarmType_HighState_TransitionTime = 10496,
			NonExclusiveDeviationAlarmType_HighState_EffectiveTransitionTime = 10497,
			NonExclusiveDeviationAlarmType_HighState_TrueState = 10498,
			NonExclusiveDeviationAlarmType_HighState_FalseState = 10499,
			NonExclusiveDeviationAlarmType_LowState = 10500,
			NonExclusiveDeviationAlarmType_LowState_Id = 10501,
			NonExclusiveDeviationAlarmType_LowState_Name = 10502,
			NonExclusiveDeviationAlarmType_LowState_Number = 10503,
			NonExclusiveDeviationAlarmType_LowState_EffectiveDisplayName = 10504,
			NonExclusiveDeviationAlarmType_LowState_TransitionTime = 10505,
			NonExclusiveDeviationAlarmType_LowState_EffectiveTransitionTime = 10506,
			NonExclusiveDeviationAlarmType_LowState_TrueState = 10507,
			NonExclusiveDeviationAlarmType_LowState_FalseState = 10508,
			NonExclusiveDeviationAlarmType_LowLowState = 10509,
			NonExclusiveDeviationAlarmType_LowLowState_Id = 10510,
			NonExclusiveDeviationAlarmType_LowLowState_Name = 10511,
			NonExclusiveDeviationAlarmType_LowLowState_Number = 10512,
			NonExclusiveDeviationAlarmType_LowLowState_EffectiveDisplayName = 10513,
			NonExclusiveDeviationAlarmType_LowLowState_TransitionTime = 10514,
			NonExclusiveDeviationAlarmType_LowLowState_EffectiveTransitionTime = 10515,
			NonExclusiveDeviationAlarmType_LowLowState_TrueState = 10516,
			NonExclusiveDeviationAlarmType_LowLowState_FalseState = 10517,
			NonExclusiveDeviationAlarmType_HighHighLimit = 10518,
			NonExclusiveDeviationAlarmType_HighLimit = 10519,
			NonExclusiveDeviationAlarmType_LowLimit = 10520,
			NonExclusiveDeviationAlarmType_LowLowLimit = 10521,
			NonExclusiveDeviationAlarmType_SetpointNode = 10522,
			DiscreteAlarmType = 10523,
			DiscreteAlarmType_EventId = 10524,
			DiscreteAlarmType_EventType = 10525,
			DiscreteAlarmType_SourceNode = 10526,
			DiscreteAlarmType_SourceName = 10527,
			DiscreteAlarmType_Time = 10528,
			DiscreteAlarmType_ReceiveTime = 10529,
			DiscreteAlarmType_LocalTime = 10530,
			DiscreteAlarmType_Message = 10531,
			DiscreteAlarmType_Severity = 10532,
			DiscreteAlarmType_ConditionName = 10533,
			DiscreteAlarmType_BranchId = 10534,
			DiscreteAlarmType_Retain = 10535,
			DiscreteAlarmType_EnabledState = 10536,
			DiscreteAlarmType_EnabledState_Id = 10537,
			DiscreteAlarmType_EnabledState_Name = 10538,
			DiscreteAlarmType_EnabledState_Number = 10539,
			DiscreteAlarmType_EnabledState_EffectiveDisplayName = 10540,
			DiscreteAlarmType_EnabledState_TransitionTime = 10541,
			DiscreteAlarmType_EnabledState_EffectiveTransitionTime = 10542,
			DiscreteAlarmType_EnabledState_TrueState = 10543,
			DiscreteAlarmType_EnabledState_FalseState = 10544,
			DiscreteAlarmType_Quality = 10545,
			DiscreteAlarmType_Quality_SourceTimestamp = 10546,
			DiscreteAlarmType_LastSeverity = 10547,
			DiscreteAlarmType_LastSeverity_SourceTimestamp = 10548,
			DiscreteAlarmType_Comment = 10549,
			DiscreteAlarmType_Comment_SourceTimestamp = 10550,
			DiscreteAlarmType_ClientUserId = 10551,
			DiscreteAlarmType_Enable = 10552,
			DiscreteAlarmType_Disable = 10553,
			DiscreteAlarmType_AddComment = 10554,
			DiscreteAlarmType_AddComment_InputArguments = 10555,
			DiscreteAlarmType_ConditionRefresh = 10556,
			DiscreteAlarmType_ConditionRefresh_InputArguments = 10557,
			DiscreteAlarmType_AckedState = 10558,
			DiscreteAlarmType_AckedState_Id = 10559,
			DiscreteAlarmType_AckedState_Name = 10560,
			DiscreteAlarmType_AckedState_Number = 10561,
			DiscreteAlarmType_AckedState_EffectiveDisplayName = 10562,
			DiscreteAlarmType_AckedState_TransitionTime = 10563,
			DiscreteAlarmType_AckedState_EffectiveTransitionTime = 10564,
			DiscreteAlarmType_AckedState_TrueState = 10565,
			DiscreteAlarmType_AckedState_FalseState = 10566,
			DiscreteAlarmType_ConfirmedState = 10567,
			DiscreteAlarmType_ConfirmedState_Id = 10568,
			DiscreteAlarmType_ConfirmedState_Name = 10569,
			DiscreteAlarmType_ConfirmedState_Number = 10570,
			DiscreteAlarmType_ConfirmedState_EffectiveDisplayName = 10571,
			DiscreteAlarmType_ConfirmedState_TransitionTime = 10572,
			DiscreteAlarmType_ConfirmedState_EffectiveTransitionTime = 10573,
			DiscreteAlarmType_ConfirmedState_TrueState = 10574,
			DiscreteAlarmType_ConfirmedState_FalseState = 10575,
			DiscreteAlarmType_Acknowledge = 10576,
			DiscreteAlarmType_Acknowledge_InputArguments = 10577,
			DiscreteAlarmType_Confirm = 10578,
			DiscreteAlarmType_Confirm_InputArguments = 10579,
			DiscreteAlarmType_ActiveState = 10580,
			DiscreteAlarmType_ActiveState_Id = 10581,
			DiscreteAlarmType_ActiveState_Name = 10582,
			DiscreteAlarmType_ActiveState_Number = 10583,
			DiscreteAlarmType_ActiveState_EffectiveDisplayName = 10584,
			DiscreteAlarmType_ActiveState_TransitionTime = 10585,
			DiscreteAlarmType_ActiveState_EffectiveTransitionTime = 10586,
			DiscreteAlarmType_ActiveState_TrueState = 10587,
			DiscreteAlarmType_ActiveState_FalseState = 10588,
			DiscreteAlarmType_SuppressedState = 10589,
			DiscreteAlarmType_SuppressedState_Id = 10590,
			DiscreteAlarmType_SuppressedState_Name = 10591,
			DiscreteAlarmType_SuppressedState_Number = 10592,
			DiscreteAlarmType_SuppressedState_EffectiveDisplayName = 10593,
			DiscreteAlarmType_SuppressedState_TransitionTime = 10594,
			DiscreteAlarmType_SuppressedState_EffectiveTransitionTime = 10595,
			DiscreteAlarmType_SuppressedState_TrueState = 10596,
			DiscreteAlarmType_SuppressedState_FalseState = 10597,
			DiscreteAlarmType_ShelvingState = 10598,
			DiscreteAlarmType_ShelvingState_CurrentState = 10599,
			DiscreteAlarmType_ShelvingState_CurrentState_Id = 10600,
			DiscreteAlarmType_ShelvingState_CurrentState_Name = 10601,
			DiscreteAlarmType_ShelvingState_CurrentState_Number = 10602,
			DiscreteAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10603,
			DiscreteAlarmType_ShelvingState_LastTransition = 10604,
			DiscreteAlarmType_ShelvingState_LastTransition_Id = 10605,
			DiscreteAlarmType_ShelvingState_LastTransition_Name = 10606,
			DiscreteAlarmType_ShelvingState_LastTransition_Number = 10607,
			DiscreteAlarmType_ShelvingState_LastTransition_TransitionTime = 10608,
			DiscreteAlarmType_ShelvingState_UnshelveTime = 10609,
			DiscreteAlarmType_ShelvingState_Unshelve = 10631,
			DiscreteAlarmType_ShelvingState_OneShotShelve = 10632,
			DiscreteAlarmType_ShelvingState_TimedShelve = 10633,
			DiscreteAlarmType_ShelvingState_TimedShelve_InputArguments = 10634,
			DiscreteAlarmType_SuppressedOrShelved = 10635,
			DiscreteAlarmType_MaxTimeShelved = 10636,
			OffNormalAlarmType = 10637,
			OffNormalAlarmType_EventId = 10638,
			OffNormalAlarmType_EventType = 10639,
			OffNormalAlarmType_SourceNode = 10640,
			OffNormalAlarmType_SourceName = 10641,
			OffNormalAlarmType_Time = 10642,
			OffNormalAlarmType_ReceiveTime = 10643,
			OffNormalAlarmType_LocalTime = 10644,
			OffNormalAlarmType_Message = 10645,
			OffNormalAlarmType_Severity = 10646,
			OffNormalAlarmType_ConditionName = 10647,
			OffNormalAlarmType_BranchId = 10648,
			OffNormalAlarmType_Retain = 10649,
			OffNormalAlarmType_EnabledState = 10650,
			OffNormalAlarmType_EnabledState_Id = 10651,
			OffNormalAlarmType_EnabledState_Name = 10652,
			OffNormalAlarmType_EnabledState_Number = 10653,
			OffNormalAlarmType_EnabledState_EffectiveDisplayName = 10654,
			OffNormalAlarmType_EnabledState_TransitionTime = 10655,
			OffNormalAlarmType_EnabledState_EffectiveTransitionTime = 10656,
			OffNormalAlarmType_EnabledState_TrueState = 10657,
			OffNormalAlarmType_EnabledState_FalseState = 10658,
			OffNormalAlarmType_Quality = 10659,
			OffNormalAlarmType_Quality_SourceTimestamp = 10660,
			OffNormalAlarmType_LastSeverity = 10661,
			OffNormalAlarmType_LastSeverity_SourceTimestamp = 10662,
			OffNormalAlarmType_Comment = 10663,
			OffNormalAlarmType_Comment_SourceTimestamp = 10664,
			OffNormalAlarmType_ClientUserId = 10665,
			OffNormalAlarmType_Enable = 10666,
			OffNormalAlarmType_Disable = 10667,
			OffNormalAlarmType_AddComment = 10668,
			OffNormalAlarmType_AddComment_InputArguments = 10669,
			OffNormalAlarmType_ConditionRefresh = 10670,
			OffNormalAlarmType_ConditionRefresh_InputArguments = 10671,
			OffNormalAlarmType_AckedState = 10672,
			OffNormalAlarmType_AckedState_Id = 10673,
			OffNormalAlarmType_AckedState_Name = 10674,
			OffNormalAlarmType_AckedState_Number = 10675,
			OffNormalAlarmType_AckedState_EffectiveDisplayName = 10676,
			OffNormalAlarmType_AckedState_TransitionTime = 10677,
			OffNormalAlarmType_AckedState_EffectiveTransitionTime = 10678,
			OffNormalAlarmType_AckedState_TrueState = 10679,
			OffNormalAlarmType_AckedState_FalseState = 10680,
			OffNormalAlarmType_ConfirmedState = 10681,
			OffNormalAlarmType_ConfirmedState_Id = 10682,
			OffNormalAlarmType_ConfirmedState_Name = 10683,
			OffNormalAlarmType_ConfirmedState_Number = 10684,
			OffNormalAlarmType_ConfirmedState_EffectiveDisplayName = 10685,
			OffNormalAlarmType_ConfirmedState_TransitionTime = 10686,
			OffNormalAlarmType_ConfirmedState_EffectiveTransitionTime = 10687,
			OffNormalAlarmType_ConfirmedState_TrueState = 10688,
			OffNormalAlarmType_ConfirmedState_FalseState = 10689,
			OffNormalAlarmType_Acknowledge = 10690,
			OffNormalAlarmType_Acknowledge_InputArguments = 10691,
			OffNormalAlarmType_Confirm = 10692,
			OffNormalAlarmType_Confirm_InputArguments = 10693,
			OffNormalAlarmType_ActiveState = 10694,
			OffNormalAlarmType_ActiveState_Id = 10695,
			OffNormalAlarmType_ActiveState_Name = 10696,
			OffNormalAlarmType_ActiveState_Number = 10697,
			OffNormalAlarmType_ActiveState_EffectiveDisplayName = 10698,
			OffNormalAlarmType_ActiveState_TransitionTime = 10699,
			OffNormalAlarmType_ActiveState_EffectiveTransitionTime = 10700,
			OffNormalAlarmType_ActiveState_TrueState = 10701,
			OffNormalAlarmType_ActiveState_FalseState = 10702,
			OffNormalAlarmType_SuppressedState = 10703,
			OffNormalAlarmType_SuppressedState_Id = 10704,
			OffNormalAlarmType_SuppressedState_Name = 10705,
			OffNormalAlarmType_SuppressedState_Number = 10706,
			OffNormalAlarmType_SuppressedState_EffectiveDisplayName = 10707,
			OffNormalAlarmType_SuppressedState_TransitionTime = 10708,
			OffNormalAlarmType_SuppressedState_EffectiveTransitionTime = 10709,
			OffNormalAlarmType_SuppressedState_TrueState = 10710,
			OffNormalAlarmType_SuppressedState_FalseState = 10711,
			OffNormalAlarmType_ShelvingState = 10712,
			OffNormalAlarmType_ShelvingState_CurrentState = 10713,
			OffNormalAlarmType_ShelvingState_CurrentState_Id = 10714,
			OffNormalAlarmType_ShelvingState_CurrentState_Name = 10715,
			OffNormalAlarmType_ShelvingState_CurrentState_Number = 10716,
			OffNormalAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10717,
			OffNormalAlarmType_ShelvingState_LastTransition = 10718,
			OffNormalAlarmType_ShelvingState_LastTransition_Id = 10719,
			OffNormalAlarmType_ShelvingState_LastTransition_Name = 10720,
			OffNormalAlarmType_ShelvingState_LastTransition_Number = 10721,
			OffNormalAlarmType_ShelvingState_LastTransition_TransitionTime = 10722,
			OffNormalAlarmType_ShelvingState_UnshelveTime = 10723,
			OffNormalAlarmType_ShelvingState_Unshelve = 10745,
			OffNormalAlarmType_ShelvingState_OneShotShelve = 10746,
			OffNormalAlarmType_ShelvingState_TimedShelve = 10747,
			OffNormalAlarmType_ShelvingState_TimedShelve_InputArguments = 10748,
			OffNormalAlarmType_SuppressedOrShelved = 10749,
			OffNormalAlarmType_MaxTimeShelved = 10750,
			TripAlarmType = 10751,
			TripAlarmType_EventId = 10752,
			TripAlarmType_EventType = 10753,
			TripAlarmType_SourceNode = 10754,
			TripAlarmType_SourceName = 10755,
			TripAlarmType_Time = 10756,
			TripAlarmType_ReceiveTime = 10757,
			TripAlarmType_LocalTime = 10758,
			TripAlarmType_Message = 10759,
			TripAlarmType_Severity = 10760,
			TripAlarmType_ConditionName = 10761,
			TripAlarmType_BranchId = 10762,
			TripAlarmType_Retain = 10763,
			TripAlarmType_EnabledState = 10764,
			TripAlarmType_EnabledState_Id = 10765,
			TripAlarmType_EnabledState_Name = 10766,
			TripAlarmType_EnabledState_Number = 10767,
			TripAlarmType_EnabledState_EffectiveDisplayName = 10768,
			TripAlarmType_EnabledState_TransitionTime = 10769,
			TripAlarmType_EnabledState_EffectiveTransitionTime = 10770,
			TripAlarmType_EnabledState_TrueState = 10771,
			TripAlarmType_EnabledState_FalseState = 10772,
			TripAlarmType_Quality = 10773,
			TripAlarmType_Quality_SourceTimestamp = 10774,
			TripAlarmType_LastSeverity = 10775,
			TripAlarmType_LastSeverity_SourceTimestamp = 10776,
			TripAlarmType_Comment = 10777,
			TripAlarmType_Comment_SourceTimestamp = 10778,
			TripAlarmType_ClientUserId = 10779,
			TripAlarmType_Enable = 10780,
			TripAlarmType_Disable = 10781,
			TripAlarmType_AddComment = 10782,
			TripAlarmType_AddComment_InputArguments = 10783,
			TripAlarmType_ConditionRefresh = 10784,
			TripAlarmType_ConditionRefresh_InputArguments = 10785,
			TripAlarmType_AckedState = 10786,
			TripAlarmType_AckedState_Id = 10787,
			TripAlarmType_AckedState_Name = 10788,
			TripAlarmType_AckedState_Number = 10789,
			TripAlarmType_AckedState_EffectiveDisplayName = 10790,
			TripAlarmType_AckedState_TransitionTime = 10791,
			TripAlarmType_AckedState_EffectiveTransitionTime = 10792,
			TripAlarmType_AckedState_TrueState = 10793,
			TripAlarmType_AckedState_FalseState = 10794,
			TripAlarmType_ConfirmedState = 10795,
			TripAlarmType_ConfirmedState_Id = 10796,
			TripAlarmType_ConfirmedState_Name = 10797,
			TripAlarmType_ConfirmedState_Number = 10798,
			TripAlarmType_ConfirmedState_EffectiveDisplayName = 10799,
			TripAlarmType_ConfirmedState_TransitionTime = 10800,
			TripAlarmType_ConfirmedState_EffectiveTransitionTime = 10801,
			TripAlarmType_ConfirmedState_TrueState = 10802,
			TripAlarmType_ConfirmedState_FalseState = 10803,
			TripAlarmType_Acknowledge = 10804,
			TripAlarmType_Acknowledge_InputArguments = 10805,
			TripAlarmType_Confirm = 10806,
			TripAlarmType_Confirm_InputArguments = 10807,
			TripAlarmType_ActiveState = 10808,
			TripAlarmType_ActiveState_Id = 10809,
			TripAlarmType_ActiveState_Name = 10810,
			TripAlarmType_ActiveState_Number = 10811,
			TripAlarmType_ActiveState_EffectiveDisplayName = 10812,
			TripAlarmType_ActiveState_TransitionTime = 10813,
			TripAlarmType_ActiveState_EffectiveTransitionTime = 10814,
			TripAlarmType_ActiveState_TrueState = 10815,
			TripAlarmType_ActiveState_FalseState = 10816,
			TripAlarmType_SuppressedState = 10817,
			TripAlarmType_SuppressedState_Id = 10818,
			TripAlarmType_SuppressedState_Name = 10819,
			TripAlarmType_SuppressedState_Number = 10820,
			TripAlarmType_SuppressedState_EffectiveDisplayName = 10821,
			TripAlarmType_SuppressedState_TransitionTime = 10822,
			TripAlarmType_SuppressedState_EffectiveTransitionTime = 10823,
			TripAlarmType_SuppressedState_TrueState = 10824,
			TripAlarmType_SuppressedState_FalseState = 10825,
			TripAlarmType_ShelvingState = 10826,
			TripAlarmType_ShelvingState_CurrentState = 10827,
			TripAlarmType_ShelvingState_CurrentState_Id = 10828,
			TripAlarmType_ShelvingState_CurrentState_Name = 10829,
			TripAlarmType_ShelvingState_CurrentState_Number = 10830,
			TripAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 10831,
			TripAlarmType_ShelvingState_LastTransition = 10832,
			TripAlarmType_ShelvingState_LastTransition_Id = 10833,
			TripAlarmType_ShelvingState_LastTransition_Name = 10834,
			TripAlarmType_ShelvingState_LastTransition_Number = 10835,
			TripAlarmType_ShelvingState_LastTransition_TransitionTime = 10836,
			TripAlarmType_ShelvingState_UnshelveTime = 10837,
			TripAlarmType_ShelvingState_Unshelve = 10859,
			TripAlarmType_ShelvingState_OneShotShelve = 10860,
			TripAlarmType_ShelvingState_TimedShelve = 10861,
			TripAlarmType_ShelvingState_TimedShelve_InputArguments = 10862,
			TripAlarmType_SuppressedOrShelved = 10863,
			TripAlarmType_MaxTimeShelved = 10864,
			AuditConditionShelvingEventType = 11093,
			AuditConditionShelvingEventType_EventId = 11094,
			AuditConditionShelvingEventType_EventType = 11095,
			AuditConditionShelvingEventType_SourceNode = 11096,
			AuditConditionShelvingEventType_SourceName = 11097,
			AuditConditionShelvingEventType_Time = 11098,
			AuditConditionShelvingEventType_ReceiveTime = 11099,
			AuditConditionShelvingEventType_LocalTime = 11100,
			AuditConditionShelvingEventType_Message = 11101,
			AuditConditionShelvingEventType_Severity = 11102,
			AuditConditionShelvingEventType_ActionTimeStamp = 11103,
			AuditConditionShelvingEventType_Status = 11104,
			AuditConditionShelvingEventType_ServerId = 11105,
			AuditConditionShelvingEventType_ClientAuditEntryId = 11106,
			AuditConditionShelvingEventType_ClientUserId = 11107,
			AuditConditionShelvingEventType_MethodId = 11108,
			AuditConditionShelvingEventType_InputArguments = 11109,
			TwoStateVariableType_TrueState = 11110,
			TwoStateVariableType_FalseState = 11111,
			ConditionType_ConditionClassId = 11112,
			ConditionType_ConditionClassName = 11113,
			DialogConditionType_ConditionClassId = 11114,
			DialogConditionType_ConditionClassName = 11115,
			AcknowledgeableConditionType_ConditionClassId = 11116,
			AcknowledgeableConditionType_ConditionClassName = 11117,
			AlarmConditionType_ConditionClassId = 11118,
			AlarmConditionType_ConditionClassName = 11119,
			AlarmConditionType_InputNode = 11120,
			LimitAlarmType_ConditionClassId = 11121,
			LimitAlarmType_ConditionClassName = 11122,
			LimitAlarmType_InputNode = 11123,
			LimitAlarmType_HighHighLimit = 11124,
			LimitAlarmType_HighLimit = 11125,
			LimitAlarmType_LowLimit = 11126,
			LimitAlarmType_LowLowLimit = 11127,
			ExclusiveLimitAlarmType_ConditionClassId = 11128,
			ExclusiveLimitAlarmType_ConditionClassName = 11129,
			ExclusiveLimitAlarmType_InputNode = 11130,
			ExclusiveLevelAlarmType_ConditionClassId = 11131,
			ExclusiveLevelAlarmType_ConditionClassName = 11132,
			ExclusiveLevelAlarmType_InputNode = 11133,
			ExclusiveRateOfChangeAlarmType_ConditionClassId = 11134,
			ExclusiveRateOfChangeAlarmType_ConditionClassName = 11135,
			ExclusiveRateOfChangeAlarmType_InputNode = 11136,
			ExclusiveDeviationAlarmType_ConditionClassId = 11137,
			ExclusiveDeviationAlarmType_ConditionClassName = 11138,
			ExclusiveDeviationAlarmType_InputNode = 11139,
			NonExclusiveLimitAlarmType_ConditionClassId = 11140,
			NonExclusiveLimitAlarmType_ConditionClassName = 11141,
			NonExclusiveLimitAlarmType_InputNode = 11142,
			NonExclusiveLevelAlarmType_ConditionClassId = 11143,
			NonExclusiveLevelAlarmType_ConditionClassName = 11144,
			NonExclusiveLevelAlarmType_InputNode = 11145,
			NonExclusiveRateOfChangeAlarmType_ConditionClassId = 11146,
			NonExclusiveRateOfChangeAlarmType_ConditionClassName = 11147,
			NonExclusiveRateOfChangeAlarmType_InputNode = 11148,
			NonExclusiveDeviationAlarmType_ConditionClassId = 11149,
			NonExclusiveDeviationAlarmType_ConditionClassName = 11150,
			NonExclusiveDeviationAlarmType_InputNode = 11151,
			DiscreteAlarmType_ConditionClassId = 11152,
			DiscreteAlarmType_ConditionClassName = 11153,
			DiscreteAlarmType_InputNode = 11154,
			OffNormalAlarmType_ConditionClassId = 11155,
			OffNormalAlarmType_ConditionClassName = 11156,
			OffNormalAlarmType_InputNode = 11157,
			OffNormalAlarmType_NormalState = 11158,
			TripAlarmType_ConditionClassId = 11159,
			TripAlarmType_ConditionClassName = 11160,
			TripAlarmType_InputNode = 11161,
			TripAlarmType_NormalState = 11162,
			BaseConditionClassType = 11163,
			ProcessConditionClassType = 11164,
			MaintenanceConditionClassType = 11165,
			SystemConditionClassType = 11166,
			HistoricalDataConfigurationType_AggregateConfiguration_TreatUncertainAsBad = 11168,
			HistoricalDataConfigurationType_AggregateConfiguration_PercentDataBad = 11169,
			HistoricalDataConfigurationType_AggregateConfiguration_PercentDataGood = 11170,
			HistoricalDataConfigurationType_AggregateConfiguration_UseSlopedExtrapolation = 11171,
			HistoryServerCapabilitiesType_AggregateFunctions = 11172,
			AggregateConfigurationType = 11187,
			AggregateConfigurationType_TreatUncertainAsBad = 11188,
			AggregateConfigurationType_PercentDataBad = 11189,
			AggregateConfigurationType_PercentDataGood = 11190,
			AggregateConfigurationType_UseSlopedExtrapolation = 11191,
			HistoryServerCapabilities = 11192,
			HistoryServerCapabilities_AccessHistoryDataCapability = 11193,
			HistoryServerCapabilities_InsertDataCapability = 11196,
			HistoryServerCapabilities_ReplaceDataCapability = 11197,
			HistoryServerCapabilities_UpdateDataCapability = 11198,
			HistoryServerCapabilities_DeleteRawCapability = 11199,
			HistoryServerCapabilities_DeleteAtTimeCapability = 11200,
			HistoryServerCapabilities_AggregateFunctions = 11201,
			HAConfiguration = 11202,
			HAConfiguration_AggregateConfiguration = 11203,
			HAConfiguration_AggregateConfiguration_TreatUncertainAsBad = 11204,
			HAConfiguration_AggregateConfiguration_PercentDataBad = 11205,
			HAConfiguration_AggregateConfiguration_PercentDataGood = 11206,
			HAConfiguration_AggregateConfiguration_UseSlopedExtrapolation = 11207,
			HAConfiguration_Stepped = 11208,
			HAConfiguration_Definition = 11209,
			HAConfiguration_MaxTimeInterval = 11210,
			HAConfiguration_MinTimeInterval = 11211,
			HAConfiguration_ExceptionDeviation = 11212,
			HAConfiguration_ExceptionDeviationFormat = 11213,
			Annotations = 11214,
			HistoricalEventFilter = 11215,
			ModificationInfo = 11216,
			HistoryModifiedData = 11217,
			ModificationInfo_Encoding_DefaultXml = 11218,
			HistoryModifiedData_Encoding_DefaultXml = 11219,
			ModificationInfo_Encoding_DefaultBinary = 11226,
			HistoryModifiedData_Encoding_DefaultBinary = 11227,
			HistoryUpdateType = 11234,
			MultiStateValueDiscreteType = 11238,
			MultiStateValueDiscreteType_Definition = 11239,
			MultiStateValueDiscreteType_ValuePrecision = 11240,
			MultiStateValueDiscreteType_EnumValues = 11241,
			HistoryServerCapabilities_AccessHistoryEventsCapability = 11242,
			HistoryServerCapabilitiesType_MaxReturnDataValues = 11268,
			HistoryServerCapabilitiesType_MaxReturnEventValues = 11269,
			HistoryServerCapabilitiesType_InsertAnnotationCapability = 11270,
			HistoryServerCapabilities_MaxReturnDataValues = 11273,
			HistoryServerCapabilities_MaxReturnEventValues = 11274,
			HistoryServerCapabilities_InsertAnnotationCapability = 11275,
			HistoryServerCapabilitiesType_InsertEventCapability = 11278,
			HistoryServerCapabilitiesType_ReplaceEventCapability = 11279,
			HistoryServerCapabilitiesType_UpdateEventCapability = 11280,
			HistoryServerCapabilities_InsertEventCapability = 11281,
			HistoryServerCapabilities_ReplaceEventCapability = 11282,
			HistoryServerCapabilities_UpdateEventCapability = 11283,
			AggregateFunction_TimeAverage2 = 11285,
			AggregateFunction_Minimum2 = 11286,
			AggregateFunction_Maximum2 = 11287,
			AggregateFunction_Range2 = 11288,
			AggregateFunction_WorstQuality2 = 11292,
			PerformUpdateType = 11293,
			UpdateStructureDataDetails = 11295,
			UpdateStructureDataDetails_Encoding_DefaultXml = 11296,
			UpdateStructureDataDetails_Encoding_DefaultBinary = 11300,
			AggregateFunction_Total2 = 11304,
			AggregateFunction_MinimumActualTime2 = 11305,
			AggregateFunction_MaximumActualTime2 = 11306,
			AggregateFunction_DurationInStateZero = 11307,
			AggregateFunction_DurationInStateNonZero = 11308,
			Server_ServerRedundancy_CurrentServerId = 11312,
			Server_ServerRedundancy_RedundantServerArray = 11313,
			Server_ServerRedundancy_ServerUriArray = 11314,
			ShelvedStateMachineType_UnshelvedToTimedShelved_TransitionNumber = 11322,
			ShelvedStateMachineType_UnshelvedToOneShotShelved_TransitionNumber = 11323,
			ShelvedStateMachineType_TimedShelvedToUnshelved_TransitionNumber = 11324,
			ShelvedStateMachineType_TimedShelvedToOneShotShelved_TransitionNumber = 11325,
			ShelvedStateMachineType_OneShotShelvedToUnshelved_TransitionNumber = 11326,
			ShelvedStateMachineType_OneShotShelvedToTimedShelved_TransitionNumber = 11327,
			ExclusiveLimitStateMachineType_LowLowToLow_TransitionNumber = 11340,
			ExclusiveLimitStateMachineType_LowToLowLow_TransitionNumber = 11341,
			ExclusiveLimitStateMachineType_HighHighToHigh_TransitionNumber = 11342,
			ExclusiveLimitStateMachineType_HighToHighHigh_TransitionNumber = 11343,
			AggregateFunction_StandardDeviationSample = 11426,
			AggregateFunction_StandardDeviationPopulation = 11427,
			AggregateFunction_VarianceSample = 11428,
			AggregateFunction_VariancePopulation = 11429,
			EnumStrings = 11432,
			ValueAsText = 11433,
			ProgressEventType = 11436,
			ProgressEventType_EventId = 11437,
			ProgressEventType_EventType = 11438,
			ProgressEventType_SourceNode = 11439,
			ProgressEventType_SourceName = 11440,
			ProgressEventType_Time = 11441,
			ProgressEventType_ReceiveTime = 11442,
			ProgressEventType_LocalTime = 11443,
			ProgressEventType_Message = 11444,
			ProgressEventType_Severity = 11445,
			SystemStatusChangeEventType = 11446,
			SystemStatusChangeEventType_EventId = 11447,
			SystemStatusChangeEventType_EventType = 11448,
			SystemStatusChangeEventType_SourceNode = 11449,
			SystemStatusChangeEventType_SourceName = 11450,
			SystemStatusChangeEventType_Time = 11451,
			SystemStatusChangeEventType_ReceiveTime = 11452,
			SystemStatusChangeEventType_LocalTime = 11453,
			SystemStatusChangeEventType_Message = 11454,
			SystemStatusChangeEventType_Severity = 11455,
			TransitionVariableType_EffectiveTransitionTime = 11456,
			FiniteTransitionVariableType_EffectiveTransitionTime = 11457,
			StateMachineType_LastTransition_EffectiveTransitionTime = 11458,
			FiniteStateMachineType_LastTransition_EffectiveTransitionTime = 11459,
			TransitionEventType_Transition_EffectiveTransitionTime = 11460,
			MultiStateValueDiscreteType_ValueAsText = 11461,
			ProgramTransitionEventType_Transition_EffectiveTransitionTime = 11462,
			ProgramTransitionAuditEventType_Transition_EffectiveTransitionTime = 11463,
			ProgramStateMachineType_LastTransition_EffectiveTransitionTime = 11464,
			ShelvedStateMachineType_LastTransition_EffectiveTransitionTime = 11465,
			AlarmConditionType_ShelvingState_LastTransition_EffectiveTransitionTime = 11466,
			LimitAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11467,
			ExclusiveLimitStateMachineType_LastTransition_EffectiveTransitionTime = 11468,
			ExclusiveLimitAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11469,
			ExclusiveLimitAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11470,
			ExclusiveLevelAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11471,
			ExclusiveLevelAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11472,
			ExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11473,
			ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11474,
			ExclusiveDeviationAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11475,
			ExclusiveDeviationAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11476,
			NonExclusiveLimitAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11477,
			NonExclusiveLevelAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11478,
			NonExclusiveRateOfChangeAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11479,
			NonExclusiveDeviationAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11480,
			DiscreteAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11481,
			OffNormalAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11482,
			TripAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11483,
			AuditActivateSessionEventType_SecureChannelId = 11485,
			OptionSetType = 11487,
			OptionSetType_OptionSetValues = 11488,
			ServerType_GetMonitoredItems = 11489,
			ServerType_GetMonitoredItems_InputArguments = 11490,
			ServerType_GetMonitoredItems_OutputArguments = 11491,
			Server_GetMonitoredItems = 11492,
			Server_GetMonitoredItems_InputArguments = 11493,
			Server_GetMonitoredItems_OutputArguments = 11494,
			GetMonitoredItemsMethodType = 11495,
			GetMonitoredItemsMethodType_InputArguments = 11496,
			GetMonitoredItemsMethodType_OutputArguments = 11497,
			MaxStringLength = 11498,
			HistoricalDataConfigurationType_StartOfArchive = 11499,
			HistoricalDataConfigurationType_StartOfOnlineArchive = 11500,
			HistoryServerCapabilitiesType_DeleteEventCapability = 11501,
			HistoryServerCapabilities_DeleteEventCapability = 11502,
			HAConfiguration_StartOfArchive = 11503,
			HAConfiguration_StartOfOnlineArchive = 11504,
			AggregateFunction_StartBound = 11505,
			AggregateFunction_EndBound = 11506,
			AggregateFunction_DeltaBounds = 11507,
			ModellingRule_OptionalPlaceholder = 11508,
			ModellingRule_OptionalPlaceholder_NamingRule = 11509,
			ModellingRule_MandatoryPlaceholder = 11510,
			ModellingRule_MandatoryPlaceholder_NamingRule = 11511,
			MaxArrayLength = 11512,
			EngineeringUnits = 11513,
			ServerType_ServerCapabilities_MaxArrayLength = 11514,
			ServerType_ServerCapabilities_MaxStringLength = 11515,
			ServerType_ServerCapabilities_OperationLimits = 11516,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerRead = 11517,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerWrite = 11519,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall = 11521,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerBrowse = 11522,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes = 11523,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds = 11524,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement = 11525,
			ServerType_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall = 11526,
			ServerType_Namespaces = 11527,
			ServerType_Namespaces_AddressSpaceFile = 11528,
			ServerType_Namespaces_AddressSpaceFile_Size = 11529,
			ServerType_Namespaces_AddressSpaceFile_Writeable = 11530,
			ServerType_Namespaces_AddressSpaceFile_UserWriteable = 11531,
			ServerType_Namespaces_AddressSpaceFile_OpenCount = 11532,
			ServerType_Namespaces_AddressSpaceFile_Open = 11533,
			ServerType_Namespaces_AddressSpaceFile_Open_InputArguments = 11534,
			ServerType_Namespaces_AddressSpaceFile_Open_OutputArguments = 11535,
			ServerType_Namespaces_AddressSpaceFile_Close = 11536,
			ServerType_Namespaces_AddressSpaceFile_Close_InputArguments = 11537,
			ServerType_Namespaces_AddressSpaceFile_Read = 11538,
			ServerType_Namespaces_AddressSpaceFile_Read_InputArguments = 11539,
			ServerType_Namespaces_AddressSpaceFile_Read_OutputArguments = 11540,
			ServerType_Namespaces_AddressSpaceFile_Write = 11541,
			ServerType_Namespaces_AddressSpaceFile_Write_InputArguments = 11542,
			ServerType_Namespaces_AddressSpaceFile_GetPosition = 11543,
			ServerType_Namespaces_AddressSpaceFile_GetPosition_InputArguments = 11544,
			ServerType_Namespaces_AddressSpaceFile_GetPosition_OutputArguments = 11545,
			ServerType_Namespaces_AddressSpaceFile_SetPosition = 11546,
			ServerType_Namespaces_AddressSpaceFile_SetPosition_InputArguments = 11547,
			ServerType_Namespaces_AddressSpaceFile_ExportNamespace = 11548,
			ServerCapabilitiesType_MaxArrayLength = 11549,
			ServerCapabilitiesType_MaxStringLength = 11550,
			ServerCapabilitiesType_OperationLimits = 11551,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerRead = 11552,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerWrite = 11554,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerMethodCall = 11556,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerBrowse = 11557,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerRegisterNodes = 11558,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds = 11559,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerNodeManagement = 11560,
			ServerCapabilitiesType_OperationLimits_MaxMonitoredItemsPerCall = 11561,
			ServerCapabilitiesType_VendorCapability = 11562,
			OperationLimitsType = 11564,
			OperationLimitsType_MaxNodesPerRead = 11565,
			OperationLimitsType_MaxNodesPerWrite = 11567,
			OperationLimitsType_MaxNodesPerMethodCall = 11569,
			OperationLimitsType_MaxNodesPerBrowse = 11570,
			OperationLimitsType_MaxNodesPerRegisterNodes = 11571,
			OperationLimitsType_MaxNodesPerTranslateBrowsePathsToNodeIds = 11572,
			OperationLimitsType_MaxNodesPerNodeManagement = 11573,
			OperationLimitsType_MaxMonitoredItemsPerCall = 11574,
			FileType = 11575,
			FileType_Size = 11576,
			FileType_Writeable = 11577,
			FileType_UserWriteable = 11578,
			FileType_OpenCount = 11579,
			FileType_Open = 11580,
			FileType_Open_InputArguments = 11581,
			FileType_Open_OutputArguments = 11582,
			FileType_Close = 11583,
			FileType_Close_InputArguments = 11584,
			FileType_Read = 11585,
			FileType_Read_InputArguments = 11586,
			FileType_Read_OutputArguments = 11587,
			FileType_Write = 11588,
			FileType_Write_InputArguments = 11589,
			FileType_GetPosition = 11590,
			FileType_GetPosition_InputArguments = 11591,
			FileType_GetPosition_OutputArguments = 11592,
			FileType_SetPosition = 11593,
			FileType_SetPosition_InputArguments = 11594,
			AddressSpaceFileType = 11595,
			AddressSpaceFileType_Size = 11596,
			AddressSpaceFileType_Writeable = 11597,
			AddressSpaceFileType_UserWriteable = 11598,
			AddressSpaceFileType_OpenCount = 11599,
			AddressSpaceFileType_Open = 11600,
			AddressSpaceFileType_Open_InputArguments = 11601,
			AddressSpaceFileType_Open_OutputArguments = 11602,
			AddressSpaceFileType_Close = 11603,
			AddressSpaceFileType_Close_InputArguments = 11604,
			AddressSpaceFileType_Read = 11605,
			AddressSpaceFileType_Read_InputArguments = 11606,
			AddressSpaceFileType_Read_OutputArguments = 11607,
			AddressSpaceFileType_Write = 11608,
			AddressSpaceFileType_Write_InputArguments = 11609,
			AddressSpaceFileType_GetPosition = 11610,
			AddressSpaceFileType_GetPosition_InputArguments = 11611,
			AddressSpaceFileType_GetPosition_OutputArguments = 11612,
			AddressSpaceFileType_SetPosition = 11613,
			AddressSpaceFileType_SetPosition_InputArguments = 11614,
			AddressSpaceFileType_ExportNamespace = 11615,
			NamespaceMetadataType = 11616,
			NamespaceMetadataType_NamespaceUri = 11617,
			NamespaceMetadataType_NamespaceVersion = 11618,
			NamespaceMetadataType_NamespacePublicationDate = 11619,
			NamespaceMetadataType_IsNamespaceSubset = 11620,
			NamespaceMetadataType_StaticNodeIdIdentifierTypes = 11621,
			NamespaceMetadataType_StaticNumericNodeIdRange = 11622,
			NamespaceMetadataType_StaticStringNodeIdPattern = 11623,
			NamespaceMetadataType_NamespaceFile = 11624,
			NamespaceMetadataType_NamespaceFile_Size = 11625,
			NamespaceMetadataType_NamespaceFile_Writeable = 11626,
			NamespaceMetadataType_NamespaceFile_UserWriteable = 11627,
			NamespaceMetadataType_NamespaceFile_OpenCount = 11628,
			NamespaceMetadataType_NamespaceFile_Open = 11629,
			NamespaceMetadataType_NamespaceFile_Open_InputArguments = 11630,
			NamespaceMetadataType_NamespaceFile_Open_OutputArguments = 11631,
			NamespaceMetadataType_NamespaceFile_Close = 11632,
			NamespaceMetadataType_NamespaceFile_Close_InputArguments = 11633,
			NamespaceMetadataType_NamespaceFile_Read = 11634,
			NamespaceMetadataType_NamespaceFile_Read_InputArguments = 11635,
			NamespaceMetadataType_NamespaceFile_Read_OutputArguments = 11636,
			NamespaceMetadataType_NamespaceFile_Write = 11637,
			NamespaceMetadataType_NamespaceFile_Write_InputArguments = 11638,
			NamespaceMetadataType_NamespaceFile_GetPosition = 11639,
			NamespaceMetadataType_NamespaceFile_GetPosition_InputArguments = 11640,
			NamespaceMetadataType_NamespaceFile_GetPosition_OutputArguments = 11641,
			NamespaceMetadataType_NamespaceFile_SetPosition = 11642,
			NamespaceMetadataType_NamespaceFile_SetPosition_InputArguments = 11643,
			NamespaceMetadataType_NamespaceFile_ExportNamespace = 11644,
			NamespacesType = 11645,
			NamespacesType_NamespaceIdentifier = 11646,
			NamespacesType_NamespaceIdentifier_NamespaceUri = 11647,
			NamespacesType_NamespaceIdentifier_NamespaceVersion = 11648,
			NamespacesType_NamespaceIdentifier_NamespacePublicationDate = 11649,
			NamespacesType_NamespaceIdentifier_IsNamespaceSubset = 11650,
			NamespacesType_NamespaceIdentifier_StaticNodeIdIdentifierTypes = 11651,
			NamespacesType_NamespaceIdentifier_StaticNumericNodeIdRange = 11652,
			NamespacesType_NamespaceIdentifier_StaticStringNodeIdPattern = 11653,
			NamespacesType_NamespaceIdentifier_NamespaceFile = 11654,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Size = 11655,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Writeable = 11656,
			NamespacesType_NamespaceIdentifier_NamespaceFile_UserWriteable = 11657,
			NamespacesType_NamespaceIdentifier_NamespaceFile_OpenCount = 11658,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Open = 11659,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Open_InputArguments = 11660,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Open_OutputArguments = 11661,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Close = 11662,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Close_InputArguments = 11663,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Read = 11664,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Read_InputArguments = 11665,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Read_OutputArguments = 11666,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Write = 11667,
			NamespacesType_NamespaceIdentifier_NamespaceFile_Write_InputArguments = 11668,
			NamespacesType_NamespaceIdentifier_NamespaceFile_GetPosition = 11669,
			NamespacesType_NamespaceIdentifier_NamespaceFile_GetPosition_InputArguments = 11670,
			NamespacesType_NamespaceIdentifier_NamespaceFile_GetPosition_OutputArguments = 11671,
			NamespacesType_NamespaceIdentifier_NamespaceFile_SetPosition = 11672,
			NamespacesType_NamespaceIdentifier_NamespaceFile_SetPosition_InputArguments = 11673,
			NamespacesType_NamespaceIdentifier_NamespaceFile_ExportNamespace = 11674,
			NamespacesType_AddressSpaceFile = 11675,
			NamespacesType_AddressSpaceFile_Size = 11676,
			NamespacesType_AddressSpaceFile_Writeable = 11677,
			NamespacesType_AddressSpaceFile_UserWriteable = 11678,
			NamespacesType_AddressSpaceFile_OpenCount = 11679,
			NamespacesType_AddressSpaceFile_Open = 11680,
			NamespacesType_AddressSpaceFile_Open_InputArguments = 11681,
			NamespacesType_AddressSpaceFile_Open_OutputArguments = 11682,
			NamespacesType_AddressSpaceFile_Close = 11683,
			NamespacesType_AddressSpaceFile_Close_InputArguments = 11684,
			NamespacesType_AddressSpaceFile_Read = 11685,
			NamespacesType_AddressSpaceFile_Read_InputArguments = 11686,
			NamespacesType_AddressSpaceFile_Read_OutputArguments = 11687,
			NamespacesType_AddressSpaceFile_Write = 11688,
			NamespacesType_AddressSpaceFile_Write_InputArguments = 11689,
			NamespacesType_AddressSpaceFile_GetPosition = 11690,
			NamespacesType_AddressSpaceFile_GetPosition_InputArguments = 11691,
			NamespacesType_AddressSpaceFile_GetPosition_OutputArguments = 11692,
			NamespacesType_AddressSpaceFile_SetPosition = 11693,
			NamespacesType_AddressSpaceFile_SetPosition_InputArguments = 11694,
			NamespacesType_AddressSpaceFile_ExportNamespace = 11695,
			SystemStatusChangeEventType_SystemState = 11696,
			SamplingIntervalDiagnosticsType_SampledMonitoredItemsCount = 11697,
			SamplingIntervalDiagnosticsType_MaxSampledMonitoredItemsCount = 11698,
			SamplingIntervalDiagnosticsType_DisabledMonitoredItemsSamplingCount = 11699,
			OptionSetType_BitMask = 11701,
			Server_ServerCapabilities_MaxArrayLength = 11702,
			Server_ServerCapabilities_MaxStringLength = 11703,
			Server_ServerCapabilities_OperationLimits = 11704,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerRead = 11705,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite = 11707,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall = 11709,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse = 11710,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes = 11711,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds = 11712,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement = 11713,
			Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall = 11714,
			Server_Namespaces = 11715,
			Server_Namespaces_AddressSpaceFile = 11716,
			Server_Namespaces_AddressSpaceFile_Size = 11717,
			Server_Namespaces_AddressSpaceFile_Writeable = 11718,
			Server_Namespaces_AddressSpaceFile_UserWriteable = 11719,
			Server_Namespaces_AddressSpaceFile_OpenCount = 11720,
			Server_Namespaces_AddressSpaceFile_Open = 11721,
			Server_Namespaces_AddressSpaceFile_Open_InputArguments = 11722,
			Server_Namespaces_AddressSpaceFile_Open_OutputArguments = 11723,
			Server_Namespaces_AddressSpaceFile_Close = 11724,
			Server_Namespaces_AddressSpaceFile_Close_InputArguments = 11725,
			Server_Namespaces_AddressSpaceFile_Read = 11726,
			Server_Namespaces_AddressSpaceFile_Read_InputArguments = 11727,
			Server_Namespaces_AddressSpaceFile_Read_OutputArguments = 11728,
			Server_Namespaces_AddressSpaceFile_Write = 11729,
			Server_Namespaces_AddressSpaceFile_Write_InputArguments = 11730,
			Server_Namespaces_AddressSpaceFile_GetPosition = 11731,
			Server_Namespaces_AddressSpaceFile_GetPosition_InputArguments = 11732,
			Server_Namespaces_AddressSpaceFile_GetPosition_OutputArguments = 11733,
			Server_Namespaces_AddressSpaceFile_SetPosition = 11734,
			Server_Namespaces_AddressSpaceFile_SetPosition_InputArguments = 11735,
			Server_Namespaces_AddressSpaceFile_ExportNamespace = 11736,
			BitFieldMaskDataType = 11737,
			OpenMethodType = 11738,
			OpenMethodType_InputArguments = 11739,
			OpenMethodType_OutputArguments = 11740,
			CloseMethodType = 11741,
			CloseMethodType_InputArguments = 11742,
			ReadMethodType = 11743,
			ReadMethodType_InputArguments = 11744,
			ReadMethodType_OutputArguments = 11745,
			WriteMethodType = 11746,
			WriteMethodType_InputArguments = 11747,
			GetPositionMethodType = 11748,
			GetPositionMethodType_InputArguments = 11749,
			GetPositionMethodType_OutputArguments = 11750,
			SetPositionMethodType = 11751,
			SetPositionMethodType_InputArguments = 11752,
			SystemOffNormalAlarmType = 11753,
			SystemOffNormalAlarmType_EventId = 11754,
			SystemOffNormalAlarmType_EventType = 11755,
			SystemOffNormalAlarmType_SourceNode = 11756,
			SystemOffNormalAlarmType_SourceName = 11757,
			SystemOffNormalAlarmType_Time = 11758,
			SystemOffNormalAlarmType_ReceiveTime = 11759,
			SystemOffNormalAlarmType_LocalTime = 11760,
			SystemOffNormalAlarmType_Message = 11761,
			SystemOffNormalAlarmType_Severity = 11762,
			SystemOffNormalAlarmType_ConditionClassId = 11763,
			SystemOffNormalAlarmType_ConditionClassName = 11764,
			SystemOffNormalAlarmType_ConditionName = 11765,
			SystemOffNormalAlarmType_BranchId = 11766,
			SystemOffNormalAlarmType_Retain = 11767,
			SystemOffNormalAlarmType_EnabledState = 11768,
			SystemOffNormalAlarmType_EnabledState_Id = 11769,
			SystemOffNormalAlarmType_EnabledState_Name = 11770,
			SystemOffNormalAlarmType_EnabledState_Number = 11771,
			SystemOffNormalAlarmType_EnabledState_EffectiveDisplayName = 11772,
			SystemOffNormalAlarmType_EnabledState_TransitionTime = 11773,
			SystemOffNormalAlarmType_EnabledState_EffectiveTransitionTime = 11774,
			SystemOffNormalAlarmType_EnabledState_TrueState = 11775,
			SystemOffNormalAlarmType_EnabledState_FalseState = 11776,
			SystemOffNormalAlarmType_Quality = 11777,
			SystemOffNormalAlarmType_Quality_SourceTimestamp = 11778,
			SystemOffNormalAlarmType_LastSeverity = 11779,
			SystemOffNormalAlarmType_LastSeverity_SourceTimestamp = 11780,
			SystemOffNormalAlarmType_Comment = 11781,
			SystemOffNormalAlarmType_Comment_SourceTimestamp = 11782,
			SystemOffNormalAlarmType_ClientUserId = 11783,
			SystemOffNormalAlarmType_Disable = 11784,
			SystemOffNormalAlarmType_Enable = 11785,
			SystemOffNormalAlarmType_AddComment = 11786,
			SystemOffNormalAlarmType_AddComment_InputArguments = 11787,
			SystemOffNormalAlarmType_ConditionRefresh = 11788,
			SystemOffNormalAlarmType_ConditionRefresh_InputArguments = 11789,
			SystemOffNormalAlarmType_AckedState = 11790,
			SystemOffNormalAlarmType_AckedState_Id = 11791,
			SystemOffNormalAlarmType_AckedState_Name = 11792,
			SystemOffNormalAlarmType_AckedState_Number = 11793,
			SystemOffNormalAlarmType_AckedState_EffectiveDisplayName = 11794,
			SystemOffNormalAlarmType_AckedState_TransitionTime = 11795,
			SystemOffNormalAlarmType_AckedState_EffectiveTransitionTime = 11796,
			SystemOffNormalAlarmType_AckedState_TrueState = 11797,
			SystemOffNormalAlarmType_AckedState_FalseState = 11798,
			SystemOffNormalAlarmType_ConfirmedState = 11799,
			SystemOffNormalAlarmType_ConfirmedState_Id = 11800,
			SystemOffNormalAlarmType_ConfirmedState_Name = 11801,
			SystemOffNormalAlarmType_ConfirmedState_Number = 11802,
			SystemOffNormalAlarmType_ConfirmedState_EffectiveDisplayName = 11803,
			SystemOffNormalAlarmType_ConfirmedState_TransitionTime = 11804,
			SystemOffNormalAlarmType_ConfirmedState_EffectiveTransitionTime = 11805,
			SystemOffNormalAlarmType_ConfirmedState_TrueState = 11806,
			SystemOffNormalAlarmType_ConfirmedState_FalseState = 11807,
			SystemOffNormalAlarmType_Acknowledge = 11808,
			SystemOffNormalAlarmType_Acknowledge_InputArguments = 11809,
			SystemOffNormalAlarmType_Confirm = 11810,
			SystemOffNormalAlarmType_Confirm_InputArguments = 11811,
			SystemOffNormalAlarmType_ActiveState = 11812,
			SystemOffNormalAlarmType_ActiveState_Id = 11813,
			SystemOffNormalAlarmType_ActiveState_Name = 11814,
			SystemOffNormalAlarmType_ActiveState_Number = 11815,
			SystemOffNormalAlarmType_ActiveState_EffectiveDisplayName = 11816,
			SystemOffNormalAlarmType_ActiveState_TransitionTime = 11817,
			SystemOffNormalAlarmType_ActiveState_EffectiveTransitionTime = 11818,
			SystemOffNormalAlarmType_ActiveState_TrueState = 11819,
			SystemOffNormalAlarmType_ActiveState_FalseState = 11820,
			SystemOffNormalAlarmType_InputNode = 11821,
			SystemOffNormalAlarmType_SuppressedState = 11822,
			SystemOffNormalAlarmType_SuppressedState_Id = 11823,
			SystemOffNormalAlarmType_SuppressedState_Name = 11824,
			SystemOffNormalAlarmType_SuppressedState_Number = 11825,
			SystemOffNormalAlarmType_SuppressedState_EffectiveDisplayName = 11826,
			SystemOffNormalAlarmType_SuppressedState_TransitionTime = 11827,
			SystemOffNormalAlarmType_SuppressedState_EffectiveTransitionTime = 11828,
			SystemOffNormalAlarmType_SuppressedState_TrueState = 11829,
			SystemOffNormalAlarmType_SuppressedState_FalseState = 11830,
			SystemOffNormalAlarmType_ShelvingState = 11831,
			SystemOffNormalAlarmType_ShelvingState_CurrentState = 11832,
			SystemOffNormalAlarmType_ShelvingState_CurrentState_Id = 11833,
			SystemOffNormalAlarmType_ShelvingState_CurrentState_Name = 11834,
			SystemOffNormalAlarmType_ShelvingState_CurrentState_Number = 11835,
			SystemOffNormalAlarmType_ShelvingState_CurrentState_EffectiveDisplayName = 11836,
			SystemOffNormalAlarmType_ShelvingState_LastTransition = 11837,
			SystemOffNormalAlarmType_ShelvingState_LastTransition_Id = 11838,
			SystemOffNormalAlarmType_ShelvingState_LastTransition_Name = 11839,
			SystemOffNormalAlarmType_ShelvingState_LastTransition_Number = 11840,
			SystemOffNormalAlarmType_ShelvingState_LastTransition_TransitionTime = 11841,
			SystemOffNormalAlarmType_ShelvingState_LastTransition_EffectiveTransitionTime = 11842,
			SystemOffNormalAlarmType_ShelvingState_UnshelveTime = 11843,
			SystemOffNormalAlarmType_ShelvingState_Unshelve = 11844,
			SystemOffNormalAlarmType_ShelvingState_OneShotShelve = 11845,
			SystemOffNormalAlarmType_ShelvingState_TimedShelve = 11846,
			SystemOffNormalAlarmType_ShelvingState_TimedShelve_InputArguments = 11847,
			SystemOffNormalAlarmType_SuppressedOrShelved = 11848,
			SystemOffNormalAlarmType_MaxTimeShelved = 11849,
			SystemOffNormalAlarmType_NormalState = 11850,
			AuditConditionCommentEventType_Comment = 11851,
			AuditConditionRespondEventType_SelectedResponse = 11852,
			AuditConditionAcknowledgeEventType_Comment = 11853,
			AuditConditionConfirmEventType_Comment = 11854,
			AuditConditionShelvingEventType_ShelvingTime = 11855,
			AuditProgramTransitionEventType = 11856,
			AuditProgramTransitionEventType_EventId = 11857,
			AuditProgramTransitionEventType_EventType = 11858,
			AuditProgramTransitionEventType_SourceNode = 11859,
			AuditProgramTransitionEventType_SourceName = 11860,
			AuditProgramTransitionEventType_Time = 11861,
			AuditProgramTransitionEventType_ReceiveTime = 11862,
			AuditProgramTransitionEventType_LocalTime = 11863,
			AuditProgramTransitionEventType_Message = 11864,
			AuditProgramTransitionEventType_Severity = 11865,
			AuditProgramTransitionEventType_ActionTimeStamp = 11866,
			AuditProgramTransitionEventType_Status = 11867,
			AuditProgramTransitionEventType_ServerId = 11868,
			AuditProgramTransitionEventType_ClientAuditEntryId = 11869,
			AuditProgramTransitionEventType_ClientUserId = 11870,
			AuditProgramTransitionEventType_MethodId = 11871,
			AuditProgramTransitionEventType_InputArguments = 11872,
			AuditProgramTransitionEventType_OldStateId = 11873,
			AuditProgramTransitionEventType_NewStateId = 11874,
			AuditProgramTransitionEventType_TransitionNumber = 11875,
			HistoricalDataConfigurationType_AggregateFunctions = 11876,
			HAConfiguration_AggregateFunctions = 11877,
			NodeClass_EnumValues = 11878,
			InstanceNode = 11879,
			TypeNode = 11880,
			NodeAttributesMask_EnumValues = 11881,
			AttributeWriteMask_EnumValues = 11882,
			BrowseResultMask_EnumValues = 11883,
			HistoryUpdateType_EnumValues = 11884,
			PerformUpdateType_EnumValues = 11885,
			EnumeratedTestType_EnumValues = 11886,
			InstanceNode_Encoding_DefaultXml = 11887,
			TypeNode_Encoding_DefaultXml = 11888,
			InstanceNode_Encoding_DefaultBinary = 11889,
			TypeNode_Encoding_DefaultBinary = 11890,
			SessionDiagnosticsObjectType_SessionDiagnostics_UnauthorizedRequestCount = 11891,
			SessionDiagnosticsVariableType_UnauthorizedRequestCount = 11892,
			OpenFileMode = 11939,
			OpenFileMode_EnumValues = 11940,
			ModelChangeStructureVerbMask = 11941,
			ModelChangeStructureVerbMask_EnumValues = 11942,
			EndpointUrlListDataType = 11943,
			NetworkGroupDataType = 11944,
			NonTransparentNetworkRedundancyType = 11945,
			NonTransparentNetworkRedundancyType_RedundancySupport = 11946,
			NonTransparentNetworkRedundancyType_ServerUriArray = 11947,
			NonTransparentNetworkRedundancyType_ServerNetworkGroups = 11948,
			EndpointUrlListDataType_Encoding_DefaultXml = 11949,
			NetworkGroupDataType_Encoding_DefaultXml = 11950,
			XmlSchema_EndpointUrlListDataType = 11951,
			XmlSchema_EndpointUrlListDataType_DataTypeVersion = 11952,
			XmlSchema_EndpointUrlListDataType_DictionaryFragment = 11953,
			XmlSchema_NetworkGroupDataType = 11954,
			XmlSchema_NetworkGroupDataType_DataTypeVersion = 11955,
			XmlSchema_NetworkGroupDataType_DictionaryFragment = 11956,
			EndpointUrlListDataType_Encoding_DefaultBinary = 11957,
			NetworkGroupDataType_Encoding_DefaultBinary = 11958,
			BinarySchema_EndpointUrlListDataType = 11959,
			BinarySchema_EndpointUrlListDataType_DataTypeVersion = 11960,
			BinarySchema_EndpointUrlListDataType_DictionaryFragment = 11961,
			BinarySchema_NetworkGroupDataType = 11962,
			BinarySchema_NetworkGroupDataType_DataTypeVersion = 11963,
			BinarySchema_NetworkGroupDataType_DictionaryFragment = 11964,
			ArrayItemType = 12021,
			ArrayItemType_Definition = 12022,
			ArrayItemType_ValuePrecision = 12023,
			ArrayItemType_InstrumentRange = 12024,
			ArrayItemType_EURange = 12025,
			ArrayItemType_EngineeringUnits = 12026,
			ArrayItemType_Title = 12027,
			ArrayItemType_AxisScaleType = 12028,
			YArrayItemType = 12029,
			YArrayItemType_Definition = 12030,
			YArrayItemType_ValuePrecision = 12031,
			YArrayItemType_InstrumentRange = 12032,
			YArrayItemType_EURange = 12033,
			YArrayItemType_EngineeringUnits = 12034,
			YArrayItemType_Title = 12035,
			YArrayItemType_AxisScaleType = 12036,
			YArrayItemType_XAxisDefinition = 12037,
			XYArrayItemType = 12038,
			XYArrayItemType_Definition = 12039,
			XYArrayItemType_ValuePrecision = 12040,
			XYArrayItemType_InstrumentRange = 12041,
			XYArrayItemType_EURange = 12042,
			XYArrayItemType_EngineeringUnits = 12043,
			XYArrayItemType_Title = 12044,
			XYArrayItemType_AxisScaleType = 12045,
			XYArrayItemType_XAxisDefinition = 12046,
			ImageItemType = 12047,
			ImageItemType_Definition = 12048,
			ImageItemType_ValuePrecision = 12049,
			ImageItemType_InstrumentRange = 12050,
			ImageItemType_EURange = 12051,
			ImageItemType_EngineeringUnits = 12052,
			ImageItemType_Title = 12053,
			ImageItemType_AxisScaleType = 12054,
			ImageItemType_XAxisDefinition = 12055,
			ImageItemType_YAxisDefinition = 12056,
			CubeItemType = 12057,
			CubeItemType_Definition = 12058,
			CubeItemType_ValuePrecision = 12059,
			CubeItemType_InstrumentRange = 12060,
			CubeItemType_EURange = 12061,
			CubeItemType_EngineeringUnits = 12062,
			CubeItemType_Title = 12063,
			CubeItemType_AxisScaleType = 12064,
			CubeItemType_XAxisDefinition = 12065,
			CubeItemType_YAxisDefinition = 12066,
			CubeItemType_ZAxisDefinition = 12067,
			NDimensionArrayItemType = 12068,
			NDimensionArrayItemType_Definition = 12069,
			NDimensionArrayItemType_ValuePrecision = 12070,
			NDimensionArrayItemType_InstrumentRange = 12071,
			NDimensionArrayItemType_EURange = 12072,
			NDimensionArrayItemType_EngineeringUnits = 12073,
			NDimensionArrayItemType_Title = 12074,
			NDimensionArrayItemType_AxisScaleType = 12075,
			NDimensionArrayItemType_AxisDefinition = 12076,
			AxisScaleEnumeration = 12077,
			AxisScaleEnumeration_EnumStrings = 12078,
			AxisInformation = 12079,
			XVType = 12080,
			AxisInformation_Encoding_DefaultXml = 12081,
			XVType_Encoding_DefaultXml = 12082,
			XmlSchema_AxisInformation = 12083,
			XmlSchema_AxisInformation_DataTypeVersion = 12084,
			XmlSchema_AxisInformation_DictionaryFragment = 12085,
			XmlSchema_XVType = 12086,
			XmlSchema_XVType_DataTypeVersion = 12087,
			XmlSchema_XVType_DictionaryFragment = 12088,
			AxisInformation_Encoding_DefaultBinary = 12089,
			XVType_Encoding_DefaultBinary = 12090,
			BinarySchema_AxisInformation = 12091,
			BinarySchema_AxisInformation_DataTypeVersion = 12092,
			BinarySchema_AxisInformation_DictionaryFragment = 12093,
			BinarySchema_XVType = 12094,
			BinarySchema_XVType_DataTypeVersion = 12095,
			BinarySchema_XVType_DictionaryFragment = 12096,
			SessionsDiagnosticsSummaryType_SessionPlaceholder = 12097,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics = 12098,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_SessionId = 12099,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_SessionName = 12100,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ClientDescription = 12101,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ServerUri = 12102,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_EndpointUrl = 12103,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_LocaleIds = 12104,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ActualSessionTimeout = 12105,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_MaxResponseMessageSize = 12106,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ClientConnectionTime = 12107,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ClientLastContactTime = 12108,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CurrentSubscriptionsCount = 12109,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CurrentMonitoredItemsCount = 12110,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CurrentPublishRequestsInQueue = 12111,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_TotalRequestCount = 12112,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_UnauthorizedRequestCount = 12113,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ReadCount = 12114,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_HistoryReadCount = 12115,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_WriteCount = 12116,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_HistoryUpdateCount = 12117,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CallCount = 12118,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CreateMonitoredItemsCount = 12119,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ModifyMonitoredItemsCount = 12120,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_SetMonitoringModeCount = 12121,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_SetTriggeringCount = 12122,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_DeleteMonitoredItemsCount = 12123,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_CreateSubscriptionCount = 12124,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_ModifySubscriptionCount = 12125,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_SetPublishingModeCount = 12126,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_PublishCount = 12127,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_RepublishCount = 12128,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_TransferSubscriptionsCount = 12129,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_DeleteSubscriptionsCount = 12130,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_AddNodesCount = 12131,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_AddReferencesCount = 12132,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_DeleteNodesCount = 12133,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_DeleteReferencesCount = 12134,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_BrowseCount = 12135,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_BrowseNextCount = 12136,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_TranslateBrowsePathsToNodeIdsCount = 12137,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_QueryFirstCount = 12138,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_QueryNextCount = 12139,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_RegisterNodesCount = 12140,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionDiagnostics_UnregisterNodesCount = 12141,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics = 12142,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_SessionId = 12143,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_ClientUserIdOfSession = 12144,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_ClientUserIdHistory = 12145,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_AuthenticationMechanism = 12146,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_Encoding = 12147,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_TransportProtocol = 12148,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_SecurityMode = 12149,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_SecurityPolicyUri = 12150,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SessionSecurityDiagnostics_ClientCertificate = 12151,
			SessionsDiagnosticsSummaryType_SessionPlaceholder_SubscriptionDiagnosticsArray = 12152,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData = 12153,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents = 12154,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData = 12155,
			ServerType_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents = 12156,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerHistoryReadData = 12157,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerHistoryReadEvents = 12158,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerHistoryUpdateData = 12159,
			ServerCapabilitiesType_OperationLimits_MaxNodesPerHistoryUpdateEvents = 12160,
			OperationLimitsType_MaxNodesPerHistoryReadData = 12161,
			OperationLimitsType_MaxNodesPerHistoryReadEvents = 12162,
			OperationLimitsType_MaxNodesPerHistoryUpdateData = 12163,
			OperationLimitsType_MaxNodesPerHistoryUpdateEvents = 12164,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData = 12165,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents = 12166,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData = 12167,
			Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents = 12168,
			NamingRuleType_EnumValues = 12169,
			ViewVersion = 12170,
			ComplexNumberType = 12171,
			DoubleComplexNumberType = 12172,
			ComplexNumberType_Encoding_DefaultXml = 12173,
			DoubleComplexNumberType_Encoding_DefaultXml = 12174,
			XmlSchema_ComplexNumberType = 12175,
			XmlSchema_ComplexNumberType_DataTypeVersion = 12176,
			XmlSchema_ComplexNumberType_DictionaryFragment = 12177,
			XmlSchema_DoubleComplexNumberType = 12178,
			XmlSchema_DoubleComplexNumberType_DataTypeVersion = 12179,
			XmlSchema_DoubleComplexNumberType_DictionaryFragment = 12180,
			ComplexNumberType_Encoding_DefaultBinary = 12181,
			DoubleComplexNumberType_Encoding_DefaultBinary = 12182,
			BinarySchema_ComplexNumberType = 12183,
			BinarySchema_ComplexNumberType_DataTypeVersion = 12184,
			BinarySchema_ComplexNumberType_DictionaryFragment = 12185,
			BinarySchema_DoubleComplexNumberType = 12186,
			BinarySchema_DoubleComplexNumberType_DataTypeVersion = 12187,
			BinarySchema_DoubleComplexNumberType_DictionaryFragment = 12188,
		}

		[Flags]
		public enum AccessLevel
		{
			CurrentRead = 0x1,
			CurrentWrite = 0x2,
			HistoryRead = 0x4,
			HistoryWrite = 0x8,
		}

		public enum ApplicationType
		{
			Server = 0,
			Client = 1,
			ClientAndServer = 2,
			DiscoveryServer = 3,
		}

		public enum ValueRank
		{
			OneOrMoreDimensions = 0,
			OneDimension = 1,
			Scalar = -1,
			Any = -2,
			ScalarOrOneDimension = -3
		}

		[Flags]
		public enum AttributeWriteMask
		{
			None = 0x0,
			AccessLevel = 0x1,
			ArrayDimensions = 0x2,
			BrowseName = 0x4,
			ContainsNoLoops = 0x8,
			DataType = 0x10,
			Description = 0x20,
			DisplayName = 0x40,
			EventNotifier = 0x80,
			Executable = 0x100,
			Historizing = 0x200,
			InverseName = 0x400,
			IsAbstract = 0x800,
			MinimumSamplingInterval = 0x1000,
			NodeClass = 0x2000,
			NodeId = 0x4000,
			Symmetric = 0x8000,
			UserAccessLevel = 0x10000,
			UserExecutable = 0x20000,
			UserWriteMask = 0x40000,
			ValueRank = 0x80000,
			WriteMask = 0x100000,
			ValueForVariableType = 0x200000,
		}

		public enum AxisScaleEnumeration
		{
			Linear = 0,
			Log = 1,
			Ln = 2,
		}

		public enum BrowseDirection
		{
			Forward = 0,
			Inverse = 1,
			Both = 2,
		}

		[Flags]
		public enum BrowseResultMask
		{
			None = 0x0,
			ReferenceTypeId = 0x1,
			IsForward = 0x2,
			NodeClass = 0x4,
			BrowseName = 0x8,
			DisplayName = 0x10,
			TypeDefinition = 0x20,
			All = 0x3F,
			ReferenceTypeInfo = 0x3,
			TargetInfo = 0x3C,
		}

		public enum ComplianceLevel
		{
			Untested = 0,
			Partial = 1,
			SelfTested = 2,
			Certified = 3,
		}

		public enum ConnectionState
		{
			Closed = 0,
			Opening = 1,
			Established = 2,
			Close = 3,
		}

		public enum DataChangeTrigger
		{
			Status = 0,
			StatusValue = 1,
			StatusValueTimestamp = 2,
		}

		public enum DeadbandType
		{
			None = 0,
			Absolute = 1,
			Percent = 2,
		}

		[Flags]
		public enum EnumeratedTestType
		{
			Red = 0x1,
			Yellow = 0x4,
			Green = 0x5,
		}

		public enum ExceptionDeviationFormat
		{
			AbsoluteValue = 0,
			PercentOfRange = 1,
			PercentOfValue = 2,
			PercentOfEURange = 3,
			Unknown = 4,
		}

		public enum ExtensionObjectBodyType
		{
			None = 0,
			BodyIsByteString = 1,
			BodyIsXmlElement = 2,
		}

		public enum FilterOperator
		{
			Equals = 0,
			IsNull = 1,
			GreaterThan = 2,
			LessThan = 3,
			GreaterThanOrEqual = 4,
			LessThanOrEqual = 5,
			Like = 6,
			Not = 7,
			Between = 8,
			InList = 9,
			And = 10,
			Or = 11,
			Cast = 12,
			InView = 13,
			OfType = 14,
			RelatedTo = 15,
			BitwiseAnd = 16,
			BitwiseOr = 17,
		}

		public enum HistoryUpdateType
		{
			Insert = 1,
			Replace = 2,
			Update = 3,
			Delete = 4,
		}

		public enum IdType
		{
			Numeric = 0,
			String = 1,
			Guid = 2,
			Opaque = 3,
		}

		public enum MessageSecurityMode
		{
			Invalid = 0,
			None = 1,
			Sign = 2,
			SignAndEncrypt = 3,
		}

		public enum SecurityPolicy
		{
			Invalid = 0,
			None,
			Basic256,
			Basic128Rsa15,
			Basic256Sha256
		}

		[Flags]
		public enum ModelChangeStructureVerbMask
		{
			NodeAdded = 0x1,
			NodeDeleted = 0x2,
			ReferenceAdded = 0x4,
			ReferenceDeleted = 0x8,
			DataTypeChanged = 0x10,
		}

		public enum MonitoringMode
		{
			Disabled = 0,
			Sampling = 1,
			Reporting = 2,
		}

		public enum NodeAttribute
		{
			None = 0,
			NodeId = 1,
			NodeClass = 2,
			BrowseName = 3,
			DisplayName = 4,
			Description = 5,
			WriteMask = 6,
			UserWriteMask = 7,
			IsAbstract = 8,
			Symmetric = 9,
			InverseName = 10,
			ContainsNoLoops = 11,
			EventNotifier = 12,
			Value = 13,
			DataType = 14,
			ValueRank = 15,
			ArrayDimensions = 16,
			AccessLevel = 17,
			UserAccessLevel = 18,
			MinimumSamplingInterval = 19,
			Historizing = 20,
			Executable = 21,
			UserExecutable = 22,
			DataTypeDefinition = 23,
			RolePermissions = 24,
			UserRolePermissions = 25,
			AccessRestrictions = 26,
			AccessLevelEx = 27,
		}

		[Flags]
		public enum NodeAttributesMask
		{
			None = 0x0,
			AccessLevel = 0x1,
			ArrayDimensions = 0x2,
			BrowseName = 0x4,
			ContainsNoLoops = 0x8,
			DataType = 0x10,
			Description = 0x20,
			DisplayName = 0x40,
			EventNotifier = 0x80,
			Executable = 0x100,
			Historizing = 0x200,
			InverseName = 0x400,
			IsAbstract = 0x800,
			MinimumSamplingInterval = 0x1000,
			NodeClass = 0x2000,
			NodeId = 0x4000,
			Symmetric = 0x8000,
			UserAccessLevel = 0x10000,
			UserExecutable = 0x20000,
			UserWriteMask = 0x40000,
			ValueRank = 0x80000,
			WriteMask = 0x100000,
			Value = 0x200000,
			All = 0x3FFFFF,
			BaseNode = 0x146064,
			Object = 0x1460E4,
			ObjectTypeOrDataType = 0x146864,
			Variable = 0x3D7277,
			VariableType = 0x3C6876,
			Method = 0x166164,
			ReferenceType = 0x14EC64,
			View = 0x1460EC,
		}

		[Flags]
		public enum NodeClass
		{
			Unspecified = 0x0,
			Object = 0x1,
			Variable = 0x2,
			Method = 0x4,
			ObjectType = 0x8,
			VariableType = 0x10,
			ReferenceType = 0x20,
			DataType = 0x40,
			View = 0x80,
		}

		public enum NodeIdType
		{
			TwoByte = 0,
			FourByte = 1,
			Numeric = 2,
			String = 3,
			Guid = 4,
			ByteString = 5,
		}

		public enum NodeIdNetType
		{
			//TwoByte,
			//FourByte,
			Numeric,
			String,
			Guid,
			ByteString,
		}

		[Flags]
		public enum OpenFileType
		{
			Read = 0x1,
			Write = 0x2,
			EraseExisiting = 0x4,
			Append = 0x8,
		}

		public enum PerformUpdateType
		{
			Insert = 1,
			Replace = 2,
			Update = 3,
			Remove = 4,
		}

		public enum RedundancySupport
		{
			None = 0,
			Cold = 1,
			Warm = 2,
			Hot = 3,
			Transparent = 4,
			HotAndMirrored = 5,
		}

		public enum SecurityTokenRequestType
		{
			Issue = 0,
			Renew = 1,
		}

		public enum ServerState
		{
			Running = 0,
			Failed = 1,
			NoConfiguration = 2,
			Suspended = 3,
			Shutdown = 4,
			Test = 5,
			CommunicationFault = 6,
			Unknown = 7,
		}

		public enum ChunkType
		{
			None = 0,
			Abort = 'A',
			Chunk = 'C',
			Final = 'F',
		}

		public enum TimestampsToReturn
		{
			Source = 0,
			Server = 1,
			Both = 2,
			Neither = 3,
		}

		public enum UserTokenType
		{
			Anonymous = 0,
			UserName = 1,
			Certificate = 2,
			IssuedToken = 3,
		}

		public enum VariantType
		{
			Null = 0,
			Boolean = 1,
			SByte = 2,
			Byte = 3,
			Int16 = 4,
			UInt16 = 5,
			Int32 = 6,
			UInt32 = 7,
			Int64 = 8,
			UInt64 = 9,
			Float = 10,
			Double = 11,
			String = 12,
			DateTime = 13,
			Guid = 14,
			ByteString = 15,
			XmlElement = 16,
			NodeId = 17,
			ExpandedNodeId = 18,
			StatusCode = 19,
			QualifiedName = 20,
			LocalizedText = 21,
			ExtensionObject = 22,
			DataValue = 23,
			Variant = 24,
			DiagnosticInfo = 25,
		}

		public enum RefType
		{
			References = 31,
			NonHierarchicalReferences = 32,
			HierarchicalReferences = 33,
			HasChild = 34,
			Organizes = 35,
			HasEventSource = 36,
			HasModellingRule = 37,
			HasEncoding = 38,
			HasDescription = 39,
			HasTypeDefinition = 40,
			GeneratesEvent = 41,
			AlwaysGeneratesEvent = 3065,
			Aggregates = 44,
			HasSubtype = 45,
			HasProperty = 46,
			HasComponent = 47,
			HasNotifier = 48,
			HasOrderedComponent = 49,
			FromState = 51,
			ToState = 52,
			HasCause = 53,
			HasEffect = 54,
			HasSubStateMachine = 117,
			HasHistoricalConfiguration = 56,
			HasTrueSubState = 9004,
			HasFalseSubState = 9005,
			HasCondition = 9006,
		}

		[Flags]
		public enum DataValueSpecifierMask
		{
			Value = 1 << 0,
			StatusCodeSpecified = 1 << 1,
			SourceTimestampSpecified = 1 << 2,
			ServerTimestampSpecified = 1 << 3,
			SourcePicosecondsSpecified = 1 << 4,
			ServerPicosecondsSpecified = 1 << 5,
		}

		public struct QualifiedName
		{
			public ushort NamespaceIndex;

			public string Name;

			public QualifiedName(string Name)
			{
				this.NamespaceIndex = 0;
				this.Name = Name;
			}

			public QualifiedName(ushort NamespaceIndex, string Name)
			{
				this.NamespaceIndex = NamespaceIndex;
				this.Name = Name;
			}

			public override bool Equals(object obj)
			{
				if (obj is QualifiedName)
				{
					return ToString() == ((QualifiedName)obj).ToString();
				}

				return base.Equals(obj);
			}

			public override int GetHashCode()
			{
				return ToString().GetHashCode();
			}

			public override string ToString()
			{
				return string.Format("[{0}] {1}", NamespaceIndex, Name ?? "");
			}
		}

		public class LocalizedText
		{
			public string Locale { get; set; }
			public string Text { get; set; }

			public LocalizedText(string Text)
			{
				this.Locale = string.Empty;
				this.Text = Text;
			}

			public LocalizedText(string Locale, string Text)
			{
				this.Locale = Locale;
				this.Text = Text;
			}

			public override string ToString()
			{
				return string.Format("[{0}] {1}", Locale, Text);
			}
		}

		public class ExtensionObject
		{
			public NodeId TypeId { get; set; }
			public byte[] Body { get; set; }

			public object Payload { get; set; }
		}

		public class DataValue
		{
			public object Value { get; protected set; }
			public uint? StatusCode { get; protected set; }
			public DateTime? SourceTimestamp { get; protected set; }
			public DateTime? ServerTimestamp { get; set; }

			public DataValue(object Value = null, uint? StatusCode = null, DateTime? SourceTimestamp = null, DateTime? ServerTimestamp = null)
			{
				this.Value = Value;
				this.StatusCode = StatusCode;
				this.SourceTimestamp = SourceTimestamp;
				this.ServerTimestamp = ServerTimestamp;
			}

			public DataValue(object Value, StatusCode? StatusCode, DateTime? SourceTimestamp = null, DateTime? ServerTimestamp = null)
			{
				this.Value = Value;
				this.StatusCode = StatusCode.HasValue ? (uint?)StatusCode.Value : null;
				this.SourceTimestamp = SourceTimestamp;
				this.ServerTimestamp = ServerTimestamp;
			}

			public byte GetEncodingMask()
			{
				byte res = 0;

				if (Value != null) { res |= (byte)DataValueSpecifierMask.Value; }
				if (StatusCode != null) { res |= (byte)DataValueSpecifierMask.StatusCodeSpecified; }
				if (SourceTimestamp != null) { res |= (byte)DataValueSpecifierMask.SourceTimestampSpecified; }
				if (ServerTimestamp != null) { res |= (byte)DataValueSpecifierMask.ServerTimestampSpecified; }

				return res;
			}
		}

		public class ReadValueId
		{
			public NodeId NodeId
			{
				get; protected set;
			}

			public NodeAttribute AttributeId
			{
				get; protected set;
			}

			public string IndexRange
			{
				get; protected set;
			}

			public QualifiedName DataEncoding
			{
				get; protected set;
			}

			public ReadValueId(NodeId NodeId, NodeAttribute AttributeId, string IndexRange, QualifiedName DataEncoding)
			{
				this.NodeId = NodeId;
				this.AttributeId = AttributeId;
				this.IndexRange = IndexRange;
				this.DataEncoding = DataEncoding;
			}
		}

		public class WriteValue
		{
			public NodeId NodeId { get; protected set; }
			public NodeAttribute AttributeId { get; protected set; }
			public string IndexRange { get; protected set; }
			public DataValue Value { get; protected set; }

			public WriteValue(NodeId NodeId, NodeAttribute AttributeId, string IndexRange, DataValue Value)
			{
				this.NodeId = NodeId;
				this.AttributeId = AttributeId;
				this.IndexRange = IndexRange;
				this.Value = Value;
			}
		}

		public class FilterOperand
		{
		}

		public class LiteralOperand : FilterOperand
		{
			public object Value { get; protected set; }

			public LiteralOperand(object Value)
			{
				this.Value = Value;
			}
		}

		public class SimpleAttributeOperand : FilterOperand
		{
			public NodeId TypeDefinitionId
			{
				get; protected set;
			}

			public QualifiedName[] BrowsePath
			{
				get; protected set;
			}

			public NodeAttribute AttributeId
			{
				get; protected set;
			}

			public string IndexRange
			{
				get; protected set;
			}

			public SimpleAttributeOperand(NodeId TypeDefinitionId, QualifiedName[] BrowsePath, NodeAttribute AttributeId, string IndexRange)
			{
				this.TypeDefinitionId = TypeDefinitionId;
				this.BrowsePath = BrowsePath;
				this.AttributeId = AttributeId;
				this.IndexRange = IndexRange;
			}

			public SimpleAttributeOperand(QualifiedName[] BrowsePath)
			{
				this.BrowsePath = BrowsePath;
			}
		}

		public class ReadRawModifiedDetails
		{
			public bool IsReadModified { get; protected set; }
			public DateTime StartTime { get; protected set; }
			public DateTime EndTime { get; protected set; }
			public UInt32 NumValuesPerNode { get; protected set; }
			public bool ReturnBounds { get; protected set; }

			public ReadRawModifiedDetails(bool IsReadModified, DateTime StartTime, DateTime EndTime, UInt32 NumValuesPerNode, bool ReturnBounds)
			{
				this.IsReadModified = IsReadModified;
				this.StartTime = StartTime;
				this.EndTime = EndTime;
				this.NumValuesPerNode = NumValuesPerNode;
				this.ReturnBounds = ReturnBounds;
			}
		}

		public class ReadEventDetails
		{
			public DateTime StartTime
			{
				get; protected set;
			}

			public DateTime EndTime
			{
				get; protected set;
			}

			public UInt32 NumValuesPerNode
			{
				get; protected set;
			}

			public SimpleAttributeOperand[] SelectClauses
			{
				get; protected set;
			}

			public ReadEventDetails(DateTime StartTime, DateTime EndTime, UInt32 NumValuesPerNode, SimpleAttributeOperand[] SelectClauses)
			{
				this.StartTime = StartTime;
				this.EndTime = EndTime;
				this.NumValuesPerNode = NumValuesPerNode;
				this.SelectClauses = SelectClauses;
			}
		}

		public class AggregateConfiguration
		{
			public bool UseServerCapabilitiesDefaults { get; protected set; }
			public bool TreatUncertainAsBad { get; protected set; }
			public double PercentDataBad { get; protected set; }
			public double PercentDataGood { get; protected set; }
			public bool UseSlopedExtrapolation { get; protected set; }

			public AggregateConfiguration(bool UseServerCapabilitiesDefaults, bool TreatUncertainAsBad, double PercentDataBad, double PercentDataGood, bool UseSlopedExtrapolation)
			{
				this.UseServerCapabilitiesDefaults = UseServerCapabilitiesDefaults;
				this.TreatUncertainAsBad = TreatUncertainAsBad;
				this.PercentDataBad = PercentDataBad;
				this.PercentDataGood = PercentDataGood;
				this.UseSlopedExtrapolation = UseSlopedExtrapolation;
			}
		}

		public class ReadProcessedDetails
		{
			public DateTime StartTime { get; protected set; }
			public DateTime EndTime { get; protected set; }
			public double ProcessingInterval { get; protected set; }
			public NodeId[] AggregateTypes { get; protected set; }
			public AggregateConfiguration Configuration { get; protected set; }

			public ReadProcessedDetails(DateTime StartTime, DateTime EndTime, double ProcessingInterval, NodeId[] AggregateTypes, AggregateConfiguration Configuration)
			{
				this.StartTime = StartTime;
				this.EndTime = EndTime;
				this.ProcessingInterval = ProcessingInterval;
				this.AggregateTypes = AggregateTypes;
				this.Configuration = Configuration;
			}
		}

		public class ReadAtTimeDetails
		{
			public DateTime[] ReqTimes { get; protected set; }
			public bool UseSimpleBounds { get; protected set; }

			public ReadAtTimeDetails(DateTime[] ReqTimes, bool UseSimpleBounds)
			{
				this.ReqTimes = ReqTimes;
				this.UseSimpleBounds = UseSimpleBounds;
			}
		}

		public class HistoryReadValueId
		{
			public NodeId NodeId
			{
				get; protected set;
			}

			public string IndexRange
			{
				get; protected set;
			}

			public QualifiedName DataEncoding
			{
				get; protected set;
			}

			public byte[] ContinuationPoint
			{
				get; protected set;
			}

			public HistoryReadValueId(NodeId NodeId, string IndexRange, QualifiedName DataEncoding, byte[] ContinuationPoint)
			{
				this.NodeId = NodeId;
				this.IndexRange = IndexRange;
				this.DataEncoding = DataEncoding;
				this.ContinuationPoint = ContinuationPoint;
			}
		}

		public class HistoryReadRawDetails
		{
			public bool IsReadModified
			{
				get; protected set;
			}

			public DateTime StartTime
			{
				get; protected set;
			}

			public DateTime EndTime
			{
				get; protected set;
			}

			public UInt32 NumValuesPerNode
			{
				get; protected set;
			}

			public bool ReturnBounds
			{
				get; protected set;
			}

			public HistoryReadRawDetails(bool IsReadModified, DateTime StartTime, DateTime EndTime, UInt32 NumValuesPerNode, bool ReturnBounds)
			{
				this.IsReadModified = IsReadModified;
				this.StartTime = StartTime;
				this.EndTime = EndTime;
				this.NumValuesPerNode = NumValuesPerNode;
				this.ReturnBounds = ReturnBounds;
			}
		}

		public class HistoryUpdateData
		{
			public PerformUpdateType PerformUpdate { get; protected set; }
			public NodeId NodeId { get; protected set; }
			public DataValue[] Value { get; protected set; }

			public HistoryUpdateData(NodeId NodeId, PerformUpdateType PerformUpdate, DataValue[] Value)
			{
				this.NodeId = NodeId;
				this.PerformUpdate = PerformUpdate;
				this.Value = Value;
			}
		}

		public class HistoryReadResult
		{
			public UInt32 StatusCode { get; protected set; }
			public byte[] ContinuationPoint { get; protected set; }
			public DataValue[] Values { get; protected set; }

			public HistoryReadResult(UInt32 StatusCode, byte[] ContinuationPoint, DataValue[] Values)
			{
				this.StatusCode = StatusCode;
				this.ContinuationPoint = ContinuationPoint;
				this.Values = Values;
			}
		}

		public class HistoryReadEventsResult
		{
			public struct Event
			{
				public object[] Fields;
			}

			public StatusCode StatusCode
			{
				get; protected set;
			}

			public byte[] ContinuationPoint
			{
				get; protected set;
			}

			public Event[] Events
			{
				get; protected set;
			}

			public HistoryReadEventsResult(StatusCode StatusCode, byte[] ContinuationPoint, Event[] Events)
			{
				this.StatusCode = StatusCode;
				this.ContinuationPoint = ContinuationPoint;
				this.Events = Events;
			}
		}

		public class CallMethodRequest
		{
			public NodeId ObjectId
			{
				get; protected set;
			}

			public NodeId MethodId
			{
				get; protected set;
			}

			public object[] InputArguments
			{
				get; protected set;
			}

			public CallMethodRequest(NodeId ObjectId, NodeId MethodId, object[] InputArguments)
			{
				this.ObjectId = ObjectId;
				this.MethodId = MethodId;
				this.InputArguments = InputArguments;
			}
		}

		public class CallMethodResult
		{
			public UInt32 StatusCode { get; protected set; }
			public UInt32[] Results { get; protected set; }
			public object[] Outputs { get; protected set; }

			public CallMethodResult(UInt32 StatusCode, UInt32[] Results, object[] Outputs)
			{
				this.StatusCode = StatusCode;
				this.Results = Results;
				this.Outputs = Outputs;
			}
		}

		public class ReferenceNode
		{
			public NodeId ReferenceType
			{
				get; protected set;
			}

			public NodeId Target
			{
				get; protected set;
			}

			public bool IsInverse
			{
				get; protected set;
			}

			public override string ToString()
			{
				return string.Format("[{0}] {1} {2}",
					ReferenceType.ToString(),
					IsInverse ? "<-" : "->",
					Target.ToString());
			}

			public ReferenceNode(NodeId ReferenceType, NodeId Target, bool IsInverse)
			{
				this.ReferenceType = ReferenceType;
				this.Target = Target;
				this.IsInverse = IsInverse;
			}
		}

		public class BrowseDescription
		{
			public NodeId Id { get; protected set; }
			public BrowseDirection Direction { get; protected set; }
			public NodeId ReferenceType { get; protected set; }
			public bool IncludeSubtypes { get; protected set; }
			public UInt32 NodeClassMask { get; protected set; }
			public BrowseResultMask ResultMask { get; protected set; }

			public BrowseDescription(NodeId Id, BrowseDirection Direction, NodeId ReferenceType, bool IncludeSubtypes, UInt32 NodeClassMask, BrowseResultMask ResultMask)
			{
				this.Id = Id;
				this.Direction = Direction;
				this.ReferenceType = ReferenceType;
				this.IncludeSubtypes = IncludeSubtypes;
				this.NodeClassMask = NodeClassMask;
				this.ResultMask = ResultMask;
			}
		}

		public class BrowseResult
		{
			public UInt32 StatusCode { get; protected set; }
			public byte[] ContinuationPoint { get; protected set; }
			public ReferenceDescription[] Refs { get; protected set; }

			public BrowseResult(UInt32 StatusCode, byte[] ContinuationPoint, ReferenceDescription[] Refs)
			{
				this.StatusCode = StatusCode;
				this.ContinuationPoint = ContinuationPoint;
				this.Refs = Refs;
			}
		}

		//public class ContinuationPointBrowse
		//{
		//	public bool IsValid
		//	{
		//		get; protected set;
		//	}

		//	public int Offset
		//	{
		//		get; protected set;
		//	}

		//	public int RequestedMaxReferencesPerNode
		//	{
		//		get; protected set;
		//	}

		//	public BrowseDescription Desc
		//	{
		//		get; protected set;
		//	}

		//	public ContinuationPointBrowse(bool IsValid, int Offset, int RequestedMaxReferencesPerNode, BrowseDescription Desc)
		//	{
		//		this.IsValid = IsValid;
		//		this.Offset = Offset;
		//		this.RequestedMaxReferencesPerNode = RequestedMaxReferencesPerNode;
		//		this.Desc = Desc;
		//	}
		//}

		public struct BrowsePathTarget
		{
			public NodeId Target;
			public UInt32 RemainingPathIndex;
		}

		public class RelativePathElement
		{
			public NodeId ReferenceTypeId
			{
				get; protected set;
			}

			public bool IsInverse
			{
				get; protected set;
			}

			public bool IncludeSubtypes
			{
				get; protected set;
			}

			public QualifiedName TargetName
			{
				get; protected set;
			}

			public RelativePathElement(NodeId ReferenceTypeId, bool IsInverse, bool IncludeSubtypes, QualifiedName TargetName)
			{
				this.ReferenceTypeId = ReferenceTypeId;
				this.IsInverse = IsInverse;
				this.IncludeSubtypes = IncludeSubtypes;
				this.TargetName = TargetName;
			}
		}

		public class BrowsePath
		{
			public NodeId StartingNode
			{
				get; protected set;
			}

			public RelativePathElement[] RelativePath
			{
				get; protected set;
			}

			public BrowsePath(NodeId StartingNode, RelativePathElement[] RelativePath)
			{
				this.StartingNode = StartingNode;
				this.RelativePath = RelativePath;
			}
		}

		public class BrowsePathResult
		{
			public StatusCode StatusCode
			{
				get; protected set;
			}

			public BrowsePathTarget[] Targets
			{
				get; protected set;
			}

			public BrowsePathResult(StatusCode StatusCode, BrowsePathTarget[] Targets)
			{
				this.StatusCode = StatusCode;
				this.Targets = Targets;
			}
		}

		public class ReferenceDescription
		{
			public NodeId ReferenceTypeId
			{
				get; protected set;
			}

			public bool IsForward
			{
				get; protected set;
			}

			public NodeId TargetId
			{
				get; protected set;
			}

			public QualifiedName BrowseName
			{
				get; protected set;
			}

			public LocalizedText DisplayName
			{
				get; protected set;
			}

			public NodeClass NodeClass
			{
				get; protected set;
			}

			public NodeId TypeDefinition
			{
				get; protected set;
			}

			public ReferenceDescription(NodeId ReferenceTypeId, bool IsForward, NodeId TargetId, QualifiedName BrowseName, LocalizedText DisplayName, NodeClass NodeClass, NodeId TypeDefinition)
			{
				this.ReferenceTypeId = ReferenceTypeId;
				this.IsForward = IsForward;
				this.TargetId = TargetId;
				this.BrowseName = BrowseName;
				this.DisplayName = DisplayName;
				this.NodeClass = NodeClass;
				this.TypeDefinition = TypeDefinition;
			}
		}

		public class ApplicationDescription
		{
			public string ApplicationUri
			{
				get; protected set;
			}

			public string ProductUri
			{
				get; protected set;
			}

			public LocalizedText ApplicationName
			{
				get; protected set;
			}

			public ApplicationType Type
			{
				get; protected set;
			}

			public string GatewayServerUri
			{
				get; protected set;
			}

			public string DiscoveryProfileUri
			{
				get; protected set;
			}

			public string[] DiscoveryUrls
			{
				get; protected set;
			}

			public ApplicationDescription(string ApplicationUri, string ProductUri, LocalizedText ApplicationName, ApplicationType Type, string GatewayServerUri, string DiscoveryProfileUri, string[] DiscoveryUrls)
			{
				this.ApplicationUri = ApplicationUri;
				this.ProductUri = ProductUri;
				this.ApplicationName = ApplicationName;
				this.Type = Type;
				this.GatewayServerUri = GatewayServerUri;
				this.DiscoveryProfileUri = DiscoveryProfileUri;
				this.DiscoveryUrls = DiscoveryUrls;
			}
		}

		public class UserTokenPolicy
		{
			public string PolicyId
			{
				get; protected set;
			}

			public UserTokenType TokenType
			{
				get; protected set;
			}

			public string IssuedTokenType
			{
				get; protected set;
			}

			public string IssuerEndpointUrl
			{
				get; protected set;
			}

			public string SecurityPolicyUri
			{
				get; protected set;
			}

			public UserTokenPolicy(string PolicyId, UserTokenType TokenType, string IssuedTokenType, string IssuerEndpointUrl, string SecurityPolicyUri)
			{
				this.PolicyId = PolicyId;
				this.TokenType = TokenType;
				this.IssuedTokenType = IssuedTokenType;
				this.IssuerEndpointUrl = IssuerEndpointUrl;
				this.SecurityPolicyUri = SecurityPolicyUri;
			}
		}

		public class EndpointDescription
		{
			public string EndpointUrl
			{
				get; protected set;
			}

			public ApplicationDescription Server
			{
				get; protected set;
			}

			public byte[] ServerCertificate
			{
				get; protected set;
			}

			public MessageSecurityMode SecurityMode
			{
				get; protected set;
			}

			public string SecurityPolicyUri
			{
				get; protected set;
			}

			public UserTokenPolicy[] UserIdentityTokens
			{
				get; protected set;
			}

			public string TransportProfileUri
			{
				get; protected set;
			}

			public byte SecurityLevel
			{
				get; protected set;
			}

			public EndpointDescription(string EndpointUrl, ApplicationDescription Server, byte[] ServerCertificate, MessageSecurityMode SecurityMode, string SecurityPolicyUri, UserTokenPolicy[] UserIdentityTokens, string TransportProfileUri, byte SecurityLevel)
			{
				this.EndpointUrl = EndpointUrl;
				this.Server = Server;
				this.ServerCertificate = ServerCertificate;
				this.SecurityMode = SecurityMode;
				this.SecurityPolicyUri = SecurityPolicyUri;
				this.UserIdentityTokens = UserIdentityTokens;
				this.TransportProfileUri = TransportProfileUri;
				this.SecurityLevel = SecurityLevel;
			}
		}

		public class ContentFilterElement
		{
			public FilterOperator Operator { get; protected set; }

			public FilterOperand[] Operands { get; protected set; }

			public ContentFilterElement(FilterOperator Operator, FilterOperand[] Operands)
			{
				this.Operator = Operator;
				this.Operands = Operands;
			}
		}

		public class EventFilter
		{
			public SimpleAttributeOperand[] SelectClauses { get; protected set; }
			public ContentFilterElement[] ContentFilters { get; protected set; }

			public EventFilter(SimpleAttributeOperand[] SelectClauses, ContentFilterElement[] ContentFilters)
			{
				this.SelectClauses = SelectClauses;
				this.ContentFilters = ContentFilters;
			}
		}

		public class MonitoringParameters
		{
			public UInt32 ClientHandle { get; protected set; }
			public double SamplingInterval { get; protected set; }
			public EventFilter Filter { get; protected set; }
			public UInt32 QueueSize { get; protected set; }
			public bool DiscardOldest { get; protected set; }

			public MonitoringParameters(UInt32 ClientHandle, double SamplingInterval, EventFilter Filter, UInt32 QueueSize, bool DiscardOldest)
			{
				this.ClientHandle = ClientHandle;
				this.SamplingInterval = SamplingInterval;
				this.Filter = Filter;
				this.QueueSize = QueueSize;
				this.DiscardOldest = DiscardOldest;
			}
		}

		public class MonitoredItemCreateRequest
		{
			public ReadValueId ItemToMonitor
			{
				get; protected set;
			}

			public MonitoringMode Mode
			{
				get; protected set;
			}

			public MonitoringParameters RequestedParameters
			{
				get; protected set;
			}

			public MonitoredItemCreateRequest(ReadValueId ItemToMonitor, MonitoringMode Mode, MonitoringParameters RequestedParameters)
			{
				this.ItemToMonitor = ItemToMonitor;
				this.Mode = Mode;
				this.RequestedParameters = RequestedParameters;
			}
		}

		public class MonitoredItemCreateResult : MonitoredItemModifyResult
		{
			public UInt32 MonitoredItemId { get; protected set; }

			public MonitoredItemCreateResult(StatusCode StatusCode, UInt32 MonitoredItemId, double RevisedSamplingInterval, UInt32 RevisedQueueSize, ExtensionObject Filter)
				: base(StatusCode, RevisedSamplingInterval, RevisedQueueSize, Filter)
			{
				this.MonitoredItemId = MonitoredItemId;
			}
		}

		public class MonitoredItemModifyResult
		{
			public StatusCode StatusCode { get; protected set; }
			public double RevisedSamplingInterval { get; protected set; }
			public UInt32 RevisedQueueSize { get; protected set; }
			public ExtensionObject Filter { get; protected set; }

			public MonitoredItemModifyResult(StatusCode StatusCode, double RevisedSamplingInterval, UInt32 RevisedQueueSize, ExtensionObject Filter)
			{
				this.StatusCode = StatusCode;
				this.RevisedSamplingInterval = RevisedSamplingInterval;
				this.RevisedQueueSize = RevisedQueueSize;
				this.Filter = Filter;
			}
		}

		public class MonitoredItemModifyRequest
		{
			public UInt32 MonitoredItemId { get; protected set; }
			public MonitoringParameters Parameters { get; protected set; }

			public MonitoredItemModifyRequest(UInt32 MonitoredItemId, MonitoringParameters Parameters)
			{
				this.MonitoredItemId = MonitoredItemId;
				this.Parameters = Parameters;
			}
		}

		public class RequestHeader
		{
			public NodeId AuthToken { get; set; }
			public DateTime Timestamp { get; set; }
			public uint RequestHandle { get; set; }
			public uint ReturnDiagnostics { get; set; }
			public string AuditEntryId { get; set; }
			public uint TimeoutHint { get; set; }
			public ExtensionObject AdditionalHeader { get; set; }

			// Current parameters at receive time
			public uint SecurityRequestID { get; set; }
			public uint SecuritySequenceNum { get; set; }
			public uint SecurityTokenID { get; set; }
		}

		public class ResponseHeader
		{
			public DateTimeOffset Timestamp { get; set; }
			public uint RequestHandle { get; set; }
			public uint ServiceResult { get; set; }
			public byte ServiceDiagnosticsMask { get; set; }
			public string[] StringTable { get; set; }
			public ExtensionObject AdditionalHeader { get; set; }

			public ResponseHeader()
			{
			}

			public ResponseHeader(RequestHeader req)
			{
				Timestamp = req.Timestamp;
				RequestHandle = req.RequestHandle;
			}
		}

		public class TLConfiguration
		{

			public uint ProtocolVersion, RecvBufferSize, SendBufferSize, MaxMessageSize, MaxChunkCount;
		}

		public class TLConnection
		{
			public TLConfiguration LocalConfig { get; set; }
			public TLConfiguration RemoteConfig { get; set; }

			public string RemoteEndpoint { get; set; }
		}

		public class EventNotification
		{
			public class Field
			{
				public SimpleAttributeOperand Operand;
				public object Value;
			}

			public Field[] Fields { get; set; }

			public EventNotification(Field[] Fields)
			{
				this.Fields = Fields;
			}
		}

		public class MonitoredItem
		{
			// Approximate because of lockless queue
			public const int MaxQueueSize = 1024;

			public int QueueSize;

			public UInt32 MonitoredItemId;
			public ReadValueId ItemToMonitor;
			public MonitoringMode Mode;
			public MonitoringParameters Parameters;

			public ConcurrentQueue<DataValue> QueueData;
			public bool QueueOverflowed;

			public Subscription ParentSubscription;

			public ConcurrentQueue<EventNotification> QueueEvent;
			public SimpleAttributeOperand[] FilterSelectClauses;

			public MonitoredItem(Subscription ParentSubscription, SimpleAttributeOperand[] FilterSelectClauses = null)
			{
				this.ParentSubscription = ParentSubscription;

				this.QueueData = new ConcurrentQueue<DataValue>();
				this.QueueEvent = new ConcurrentQueue<EventNotification>();
				this.FilterSelectClauses = FilterSelectClauses;

				QueueOverflowed = false;
			}
		}

		public class Subscription
		{
			public enum ChangeNotificationType
			{
				// Only publish keep-alive
				None = 0,
				// Notification with next publication cycle
				AtPublish,
				// Notification with forced publish cycle interval = 0
				Immediate,
			};

			public ChangeNotificationType ChangeNotification;

			public UInt32 SubscriptionId, LifetimeCount, MaxKeepAliveCount, MaxNotificationsPerPublish;
			public UInt32 SequenceNumber;

			public double PublishingInterval;
			public bool PublishingEnabled;
			public byte Priority;

			public DateTime PublishPreviousTime;
			public TimeSpan PublishInterval, PublishKeepAliveInterval;

			public Dictionary<UInt32, MonitoredItem> MonitoredItems;

			public Subscription()
			{
				SubscriptionId = UInt32.MaxValue;
				PublishingEnabled = false;
				SequenceNumber = 1;

				PublishingInterval = 0;
				LifetimeCount = 0;
				MaxKeepAliveCount = 0;
				MaxNotificationsPerPublish = 0;

				PublishPreviousTime = DateTime.MinValue;
				PublishInterval = TimeSpan.Zero;
				PublishKeepAliveInterval = TimeSpan.Zero;

				Priority = 0;

				ChangeNotification = ChangeNotificationType.None;
				MonitoredItems = new Dictionary<uint, MonitoredItem>();
			}
		}

		public class SLSequence
		{
			// UA_SecureConversationMessageHeader SecureConversationMessageHeader;
			// UA_SymmetricAlgorithmSecurityHeader SymmetricAlgorithmSecurityHeader;
			public uint SequenceNumber { get; set; }
			public uint RequestId { get; set; }
		}

		public class SLChannel
		{
			public class Keyset
			{
				public byte[] SymSignKey { get; protected set; }
				public byte[] SymEncKey { get; protected set; }
				public byte[] SymIV { get; protected set; }

				public Keyset(byte[] SymSignKey, byte[] SymEncKey, byte[] SymIV)
				{
					this.SymSignKey = SymSignKey;
					this.SymEncKey = SymEncKey;
					this.SymIV = SymIV;
				}

				public Keyset()
				{
					this.SymSignKey = null;
					this.SymEncKey = null;
					this.SymIV = null;
				}
			}

			public int ID { get; set; }
			public ConnectionState SLState { get; set; }

			public X509Certificate2 RemoteCertificate { get; set; }
			public byte[] RemoteCertificateString { get; set; }

			public object Session { get; set; }

			public TLConnection TL { get; set; }
			public IPEndPoint Endpoint { get; set; }

			public SLSequence LocalSequence { get; set; }
			public SLSequence RemoteSequence { get; set; }
			public SecurityPolicy SecurityPolicy { get; set; }
			public MessageSecurityMode MessageSecurityMode { get; set; }

			public uint ChannelID { get; set; }
			public uint TokenID { get; set; }
			public UInt32 TokenLifetime { get; set; }
			public DateTimeOffset TokenCreatedAt { get; set; }

			public uint? PrevChannelID { get; set; }
			public uint? PrevTokenID { get; set; }

			public NodeId AuthToken { get; set; }
			public NodeId SessionIdToken { get; set; }

			public byte[] LocalNonce { get; set; }
			public byte[] RemoteNonce { get; set; }
			public byte[] SessionIssuedNonce { get; set; }

			public Keyset[] LocalKeysets { get; set; }
			public Keyset[] RemoteKeysets { get; set; }
		}

		public class AddNodesItem
		{
			public NodeId ParentNodeId { get; set; }
			public NodeId ReferenceTypeId { get; set; }
			public NodeId RequestedNewNodeId { get; set; }
			public QualifiedName BrowseName { get; set; }
			public NodeClass NodeClass { get; set; }
			public ExtensionObject NodeAttributes { get; set; }
			public NodeId TypeDefinition { get; set; }
		}

		public class AddNodesResult
		{
			public StatusCode StatusCode { get; }

			public NodeId AddedNodeId { get; }

			public AddNodesResult(StatusCode statusCode, NodeId addedNodeId)
			{
				StatusCode = statusCode;
				AddedNodeId = addedNodeId;
			}
		}

		public class ObjectAttributes
		{
			public NodeAttributesMask SpecifiedAttributes { get; set; }
			public LocalizedText DisplayName { get; set; }
			public LocalizedText Description { get; set; }
			public uint WriteMask { get; set; }
			public uint UserWriteMask { get; set; }
			public byte EventNotifier { get; set; }

			public ObjectAttributes()
			{
				SpecifiedAttributes = NodeAttributesMask.DisplayName
											| NodeAttributesMask.Description
											| NodeAttributesMask.WriteMask
											| NodeAttributesMask.UserWriteMask
											| NodeAttributesMask.EventNotifier;
			}
		}

		public class ObjectTypeAttributes
		{
			public NodeAttributesMask SpecifiedAttributes { get; set; }
			public LocalizedText DisplayName { get; set; }
			public LocalizedText Description { get; set; }
			public uint WriteMask { get; set; }
			public uint UserWriteMask { get; set; }
			public bool IsAbstract { get; set; }

			public ObjectTypeAttributes()
			{
				SpecifiedAttributes = NodeAttributesMask.DisplayName
											| NodeAttributesMask.Description
											| NodeAttributesMask.WriteMask
											| NodeAttributesMask.UserWriteMask
											| NodeAttributesMask.IsAbstract;
			}
		}

		public class VariableAttributes
		{
			public NodeAttributesMask SpecifiedAttributes { get; set; }
			public LocalizedText DisplayName { get; set; }
			public LocalizedText Description { get; set; }
			public uint WriteMask { get; set; }
			public uint UserWriteMask { get; set; }
			public object Value { get; set; }
			public NodeId DataType { get; set; }
			public int ValueRank { get; set; }
			public uint[] ArrayDimensions { get; set; }
			public byte AccessLevel { get; set; }
			public byte UserAccessLevel { get; set; }
			public double MinimumSamplingInterval { get; set; }
			public bool Historizing { get; set; }

			public VariableAttributes()
			{
				SpecifiedAttributes = NodeAttributesMask.DisplayName
					| NodeAttributesMask.Description
					| NodeAttributesMask.WriteMask
					| NodeAttributesMask.UserWriteMask
					| NodeAttributesMask.Value
					| NodeAttributesMask.DataType
					| NodeAttributesMask.ValueRank
					| NodeAttributesMask.ArrayDimensions
					| NodeAttributesMask.AccessLevel
					| NodeAttributesMask.UserAccessLevel
					| NodeAttributesMask.MinimumSamplingInterval
					| NodeAttributesMask.Historizing;

				Description = new LocalizedText("");
				DisplayName = new LocalizedText("");
				WriteMask = 0;
				UserWriteMask = 0;
				Value = 0;
				DataType = new NodeId(0, 0);
				ValueRank = 0;
				ArrayDimensions = new uint[0];
				AccessLevel = 0;
				UserAccessLevel = 0;
				MinimumSamplingInterval = 0;
				Historizing = false;
			}
		}

		public class VariableTypeAttributes
		{
			public NodeAttributesMask SpecifiedAttributes { get; set; }
			public LocalizedText DisplayName { get; set; }
			public LocalizedText Description { get; set; }
			public uint WriteMask { get; set; }
			public uint UserWriteMask { get; set; }
			public object Value { get; set; }
			public NodeId DataType { get; set; }
			public int ValueRank { get; set; }
			public uint[] ArrayDimensions { get; set; }
			public bool IsAbstract { get; set; }

			public VariableTypeAttributes()
			{
				// 2112
				SpecifiedAttributes = NodeAttributesMask.DisplayName
					| NodeAttributesMask.Description
					| NodeAttributesMask.WriteMask
					| NodeAttributesMask.UserWriteMask
					| NodeAttributesMask.Value
					| NodeAttributesMask.DataType
					| NodeAttributesMask.ValueRank
					| NodeAttributesMask.ArrayDimensions
					| NodeAttributesMask.IsAbstract;

				Description = new LocalizedText("");
				DisplayName = new LocalizedText("");
				WriteMask = 0;
				UserWriteMask = 0;
				Value = 0;
				DataType = new NodeId(0, 0);
				ValueRank = 0;
				ArrayDimensions = new uint[0];
				IsAbstract = false;
			}

		}

		public class DeleteNodesItem
		{
			public NodeId NodeId { get; }
			public Boolean DeleteTargetReferences { get; }

			public DeleteNodesItem(NodeId nodeId, bool deleteTargetReferences)
			{
				NodeId = nodeId;
				DeleteTargetReferences = deleteTargetReferences;
			}
		}

		public class AddReferencesItem
		{
			public NodeId SourceNodeId { get; set; }

			public NodeId ReferenceTypeId { get; set; }

			public Boolean IsForward { get; set; }

			public String TargetServerUri { get; set; }

			public NodeId TargetNodeId { get; set; }

			public NodeClass TargetNodeClass { get; set; }
		}

		public class DeleteReferencesItem
		{
			public NodeId SourceNodeId { get; set; }

			public NodeId ReferenceTypeId { get; set; }

			public Boolean IsForward { get; set; }

			public NodeId TargetNodeId { get; set; }

			public Boolean DeleteBidirectional { get; set; }
		}
	}
}
