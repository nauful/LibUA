namespace LibUA
{
    namespace Core
    {
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
    }
}
