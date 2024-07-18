﻿namespace LibUA
{
    namespace Core
    {
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
    }
}
