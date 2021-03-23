
// Type: LibUA.Core.VariableAttributes



namespace LibUA.Core
{
    public class VariableAttributes : VariableTypeAttributes
    {
        public byte AccessLevel { get; set; }

        public byte UserAccessLevel { get; set; }

        public double MinimumSamplingInterval { get; set; }

        public bool Historizing { get; set; }

        public VariableAttributes()
        {
            this.SpecifiedAttributes = NodeAttributesMask.AccessLevel | NodeAttributesMask.ArrayDimensions | NodeAttributesMask.DataType | NodeAttributesMask.Description | NodeAttributesMask.DisplayName | NodeAttributesMask.Historizing | NodeAttributesMask.MinimumSamplingInterval | NodeAttributesMask.UserAccessLevel | NodeAttributesMask.UserWriteMask | NodeAttributesMask.ValueRank | NodeAttributesMask.WriteMask | NodeAttributesMask.Value;
            this.Description = new LocalizedText("");
            this.DisplayName = new LocalizedText("");
            this.WriteMask = 0U;
            this.UserWriteMask = 0U;
            this.Value = 0;
            this.DataType = new NodeId(0, 0U);
            this.ValueRank = 0;
            this.ArrayDimensions = new uint[0];
            this.AccessLevel = 0;
            this.UserAccessLevel = 0;
            this.MinimumSamplingInterval = 0.0;
            this.Historizing = false;
        }
    }
}
