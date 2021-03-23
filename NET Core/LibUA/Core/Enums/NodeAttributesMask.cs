
// Type: LibUA.Core.NodeAttributesMask



using System;

namespace LibUA.Core
{
    [Flags]
    public enum NodeAttributesMask
    {
        None = 0,
        AccessLevel = 1,
        ArrayDimensions = 2,
        BrowseName = 4,
        ContainsNoLoops = 8,
        DataType = 16, // 0x00000010
        Description = 32, // 0x00000020
        DisplayName = 64, // 0x00000040
        EventNotifier = 128, // 0x00000080
        Executable = 256, // 0x00000100
        Historizing = 512, // 0x00000200
        InverseName = 1024, // 0x00000400
        IsAbstract = 2048, // 0x00000800
        MinimumSamplingInterval = 4096, // 0x00001000
        NodeClass = 8192, // 0x00002000
        NodeId = 16384, // 0x00004000
        Symmetric = 32768, // 0x00008000
        UserAccessLevel = 65536, // 0x00010000
        UserExecutable = 131072, // 0x00020000
        UserWriteMask = 262144, // 0x00040000
        ValueRank = 524288, // 0x00080000
        WriteMask = 1048576, // 0x00100000
        Value = 2097152, // 0x00200000
        All = Value | WriteMask | ValueRank | UserWriteMask | UserExecutable | UserAccessLevel | Symmetric | NodeId | NodeClass | MinimumSamplingInterval | IsAbstract | InverseName | Historizing | Executable | EventNotifier | DisplayName | Description | DataType | ContainsNoLoops | BrowseName | ArrayDimensions | AccessLevel, // 0x003FFFFF
        BaseNode = WriteMask | UserWriteMask | NodeId | NodeClass | DisplayName | Description | BrowseName, // 0x00146064
        Object = BaseNode | EventNotifier, // 0x001460E4
        ObjectTypeOrDataType = BaseNode | IsAbstract, // 0x00146864
        Variable = BaseNode | Value | ValueRank | UserAccessLevel | MinimumSamplingInterval | Historizing | DataType | ArrayDimensions | AccessLevel, // 0x003D7277
        VariableType = ObjectTypeOrDataType | Value | ValueRank | DataType | ArrayDimensions, // 0x003C6876
        Method = BaseNode | UserExecutable | Executable, // 0x00166164
        ReferenceType = ObjectTypeOrDataType | Symmetric | InverseName, // 0x0014EC64
        View = Object | ContainsNoLoops, // 0x001460EC
    }
}
