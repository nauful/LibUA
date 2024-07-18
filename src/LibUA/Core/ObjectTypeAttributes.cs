namespace LibUA
{
    namespace Core
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
                SpecifiedAttributes = NodeAttributesMask.DisplayName
                                            | NodeAttributesMask.Description
                                            | NodeAttributesMask.WriteMask
                                            | NodeAttributesMask.UserWriteMask
                                            | NodeAttributesMask.IsAbstract;
            }
        }
    }
}
