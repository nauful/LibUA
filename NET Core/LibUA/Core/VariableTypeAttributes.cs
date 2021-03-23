
// Type: LibUA.Core.VariableTypeAttributes



namespace LibUA.Core
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
            this.SpecifiedAttributes = NodeAttributesMask.ArrayDimensions | NodeAttributesMask.DataType | NodeAttributesMask.Description | NodeAttributesMask.DisplayName | NodeAttributesMask.IsAbstract | NodeAttributesMask.UserWriteMask | NodeAttributesMask.ValueRank | NodeAttributesMask.WriteMask | NodeAttributesMask.Value;
            this.Description = new LocalizedText("");
            this.DisplayName = new LocalizedText("");
            this.WriteMask = 0U;
            this.UserWriteMask = 0U;
            this.Value = 0;
            this.DataType = new NodeId(0, 0U);
            this.ValueRank = 0;
            this.ArrayDimensions = new uint[0];
            this.IsAbstract = false;
        }
    }
}
