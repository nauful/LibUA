
// Type: LibUA.Core.RequestCode



namespace LibUA.Core
{
    public enum RequestCode : uint
    {
        ServiceFault = 397, // 0x0000018D
        TestStackRequest = 410, // 0x0000019A
        TestStackResponse = 413, // 0x0000019D
        TestStackExRequest = 416, // 0x000001A0
        TestStackExResponse = 419, // 0x000001A3
        FindServersRequest = 422, // 0x000001A6
        FindServersResponse = 425, // 0x000001A9
        GetEndpointsRequest = 428, // 0x000001AC
        GetEndpointsResponse = 431, // 0x000001AF
        RegisterServerRequest = 437, // 0x000001B5
        RegisterServerResponse = 440, // 0x000001B8
        OpenSecureChannelRequest = 446, // 0x000001BE
        OpenSecureChannelResponse = 449, // 0x000001C1
        CloseSecureChannelRequest = 452, // 0x000001C4
        CloseSecureChannelResponse = 455, // 0x000001C7
        CreateSessionRequest = 461, // 0x000001CD
        CreateSessionResponse = 464, // 0x000001D0
        ActivateSessionRequest = 467, // 0x000001D3
        ActivateSessionResponse = 470, // 0x000001D6
        CloseSessionRequest = 473, // 0x000001D9
        CloseSessionResponse = 476, // 0x000001DC
        CancelRequest = 479, // 0x000001DF
        CancelResponse = 482, // 0x000001E2
        AddNodesRequest = 488, // 0x000001E8
        AddNodesResponse = 491, // 0x000001EB
        AddReferencesRequest = 494, // 0x000001EE
        AddReferencesResponse = 497, // 0x000001F1
        DeleteNodesRequest = 500, // 0x000001F4
        DeleteNodesResponse = 503, // 0x000001F7
        DeleteReferencesRequest = 506, // 0x000001FA
        DeleteReferencesResponse = 509, // 0x000001FD
        BrowseRequest = 527, // 0x0000020F
        BrowseResponse = 530, // 0x00000212
        BrowseNextRequest = 533, // 0x00000215
        BrowseNextResponse = 536, // 0x00000218
        TranslateBrowsePathsToNodeIdsRequest = 554, // 0x0000022A
        TranslateBrowsePathsToNodeIdsResponse = 557, // 0x0000022D
        RegisterNodesRequest = 560, // 0x00000230
        RegisterNodesResponse = 563, // 0x00000233
        UnregisterNodesRequest = 566, // 0x00000236
        UnregisterNodesResponse = 569, // 0x00000239
        QueryFirstRequest = 615, // 0x00000267
        QueryFirstResponse = 618, // 0x0000026A
        QueryNextRequest = 621, // 0x0000026D
        QueryNextResponse = 624, // 0x00000270
        ReadRequest = 631, // 0x00000277
        ReadResponse = 634, // 0x0000027A
        HistoryReadRequest = 664, // 0x00000298
        HistoryReadResponse = 667, // 0x0000029B
        WriteRequest = 673, // 0x000002A1
        WriteResponse = 676, // 0x000002A4
        HistoryUpdateRequest = 700, // 0x000002BC
        HistoryUpdateResponse = 703, // 0x000002BF
        CallMethodRequest = 706, // 0x000002C2
        CallRequest = 712, // 0x000002C8
        CallResponse = 715, // 0x000002CB
        MonitoredItemCreateRequest = 745, // 0x000002E9
        CreateMonitoredItemsRequest = 751, // 0x000002EF
        CreateMonitoredItemsResponse = 754, // 0x000002F2
        MonitoredItemModifyRequest = 757, // 0x000002F5
        ModifyMonitoredItemsRequest = 763, // 0x000002FB
        ModifyMonitoredItemsResponse = 766, // 0x000002FE
        SetMonitoringModeRequest = 769, // 0x00000301
        SetMonitoringModeResponse = 772, // 0x00000304
        SetTriggeringRequest = 775, // 0x00000307
        SetTriggeringResponse = 778, // 0x0000030A
        DeleteMonitoredItemsRequest = 781, // 0x0000030D
        DeleteMonitoredItemsResponse = 784, // 0x00000310
        CreateSubscriptionRequest = 787, // 0x00000313
        CreateSubscriptionResponse = 790, // 0x00000316
        ModifySubscriptionRequest = 793, // 0x00000319
        ModifySubscriptionResponse = 796, // 0x0000031C
        SetPublishingModeRequest = 799, // 0x0000031F
        SetPublishingModeResponse = 802, // 0x00000322
        PublishRequest = 826, // 0x0000033A
        PublishResponse = 829, // 0x0000033D
        RepublishRequest = 832, // 0x00000340
        RepublishResponse = 835, // 0x00000343
        TransferSubscriptionsRequest = 841, // 0x00000349
        TransferSubscriptionsResponse = 844, // 0x0000034C
        DeleteSubscriptionsRequest = 847, // 0x0000034F
        DeleteSubscriptionsResponse = 850, // 0x00000352
        CustomRawResponse = 1001, // 0x000003E9
        CustomRawRequest = 1002, // 0x000003EA
    }
}
