namespace LibUA
{
    namespace Core
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
                SpecifiedAttributes = NodeAttributesMask.DisplayName
                                            | NodeAttributesMask.Description
                                            | NodeAttributesMask.WriteMask
                                            | NodeAttributesMask.UserWriteMask
                                            | NodeAttributesMask.EventNotifier;
            }
        }
    }
}
