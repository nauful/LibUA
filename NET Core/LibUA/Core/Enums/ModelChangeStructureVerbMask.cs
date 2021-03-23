
// Type: LibUA.Core.ModelChangeStructureVerbMask



using System;

namespace LibUA.Core
{
    [Flags]
    public enum ModelChangeStructureVerbMask
    {
        NodeAdded = 1,
        NodeDeleted = 2,
        ReferenceAdded = 4,
        ReferenceDeleted = 8,
        DataTypeChanged = 16, // 0x00000010
    }
}
