
// Type: LibUA.Core.ObjectAttributes



namespace LibUA.Core
{
    public class ObjectAttributes
    {
        public NodeAttributesMask SpecifiedAttributes { get; set; }

        public LocalizedText DisplayName { get; set; }

        public LocalizedText Description { get; set; }

        public uint WriteMask { get; set; }

        public uint UserWriteMask { get; set; }

        public byte EventNotifier { get; set; }

        public ObjectAttributes()
        {
            this.SpecifiedAttributes = NodeAttributesMask.Description | NodeAttributesMask.DisplayName | NodeAttributesMask.EventNotifier | NodeAttributesMask.UserWriteMask | NodeAttributesMask.WriteMask;
        }
    }
}
