namespace LibUA
{
    namespace Core
    {
        public enum ValueRank
        {
            OneOrMoreDimensions = 0,
            OneDimension = 1,
            Scalar = -1,
            Any = -2,
            ScalarOrOneDimension = -3
        }
    }
}
