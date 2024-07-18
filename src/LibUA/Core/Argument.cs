namespace LibUA
{
    namespace Core
    {
        public class Argument
        {
            public string Name { get; }
            public NodeId DataType { get; }
            public int ValueRank { get; }
            public uint[] ArrayDimensions { get; }
            public LocalizedText Description { get; }

            public Argument(string name, NodeId dataType, int valueRank, uint[] arrayDimensions, LocalizedText description)
            {
                Name = name;
                DataType = dataType;
                ValueRank = valueRank;
                ArrayDimensions = arrayDimensions;
                Description = description;
            }
        }
    }
}
