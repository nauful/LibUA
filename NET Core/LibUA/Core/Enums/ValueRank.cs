
// Type: LibUA.Core.ValueRank



namespace LibUA.Core
{
    public enum ValueRank
    {
        ScalarOrOneDimension = -3, // 0xFFFFFFFD
        Any = -2, // 0xFFFFFFFE
        Scalar = -1, // 0xFFFFFFFF
        OneOrMoreDimensions = 0,
        OneDimension = 1,
    }
}
