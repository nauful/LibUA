
// Type: LibUA.Core.BrowseResultMask



using System;

namespace LibUA.Core
{
    [Flags]
    public enum BrowseResultMask
    {
        None = 0,
        ReferenceTypeId = 1,
        IsForward = 2,
        NodeClass = 4,
        BrowseName = 8,
        DisplayName = 16, // 0x00000010
        TypeDefinition = 32, // 0x00000020
        All = TypeDefinition | DisplayName | BrowseName | NodeClass | IsForward | ReferenceTypeId, // 0x0000003F
        ReferenceTypeInfo = IsForward | ReferenceTypeId, // 0x00000003
        TargetInfo = TypeDefinition | DisplayName | BrowseName | NodeClass, // 0x0000003C
    }
}
