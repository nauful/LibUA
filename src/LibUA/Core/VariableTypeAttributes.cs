namespace LibUA
{
    namespace Core
    {
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
    }
}
