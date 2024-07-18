using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum ModelChangeStructureVerbMask
        {
            NodeAdded = 0x1,
            NodeDeleted = 0x2,
            ReferenceAdded = 0x4,
            ReferenceDeleted = 0x8,
            DataTypeChanged = 0x10,
        }
    }
}
