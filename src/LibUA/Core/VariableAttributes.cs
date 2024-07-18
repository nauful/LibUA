namespace LibUA
{
    namespace Core
    {
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
    }
}
