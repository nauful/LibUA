
// Type: LibUA.Core.RefType



namespace LibUA.Core
{
    public enum RefType
    {
        References = 31, // 0x0000001F
        NonHierarchicalReferences = 32, // 0x00000020
        HierarchicalReferences = 33, // 0x00000021
        HasChild = 34, // 0x00000022
        Organizes = 35, // 0x00000023
        HasEventSource = 36, // 0x00000024
        HasModellingRule = 37, // 0x00000025
        HasEncoding = 38, // 0x00000026
        HasDescription = 39, // 0x00000027
        HasTypeDefinition = 40, // 0x00000028
        GeneratesEvent = 41, // 0x00000029
        Aggregates = 44, // 0x0000002C
        HasSubtype = 45, // 0x0000002D
        HasProperty = 46, // 0x0000002E
        HasComponent = 47, // 0x0000002F
        HasNotifier = 48, // 0x00000030
        HasOrderedComponent = 49, // 0x00000031
        FromState = 51, // 0x00000033
        ToState = 52, // 0x00000034
        HasCause = 53, // 0x00000035
        HasEffect = 54, // 0x00000036
        HasHistoricalConfiguration = 56, // 0x00000038
        HasSubStateMachine = 117, // 0x00000075
        AlwaysGeneratesEvent = 3065, // 0x00000BF9
        HasTrueSubState = 9004, // 0x0000232C
        HasFalseSubState = 9005, // 0x0000232D
        HasCondition = 9006, // 0x0000232E
    }
}
