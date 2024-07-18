using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum BrowseResultMask
        {
            None = 0x0,
            ReferenceTypeId = 0x1,
            IsForward = 0x2,
            NodeClass = 0x4,
            BrowseName = 0x8,
            DisplayName = 0x10,
            TypeDefinition = 0x20,
            All = 0x3F,
            ReferenceTypeInfo = 0x3,
            TargetInfo = 0x3C,
        }
    }
}
