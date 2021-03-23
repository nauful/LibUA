
// Type: LibUA.Core.ObjectTypeAttributes



namespace LibUA.Core
{
    public class ObjectTypeAttributes
    {
        public NodeAttributesMask SpecifiedAttributes { get; set; }

        public LocalizedText DisplayName { get; set; }

        public LocalizedText Description { get; set; }

        public uint WriteMask { get; set; }

        public uint UserWriteMask { get; set; }

        public bool IsAbstract { get; set; }

        public ObjectTypeAttributes()
        {
            this.SpecifiedAttributes = NodeAttributesMask.Description | NodeAttributesMask.DisplayName | NodeAttributesMask.IsAbstract | NodeAttributesMask.UserWriteMask | NodeAttributesMask.WriteMask;
        }
    }
}
