
// Type: LibUA.Core.NodeClass



using System;

namespace LibUA.Core
{
    [Flags]
    public enum NodeClass
    {
        Unspecified = 0,
        Object = 1,
        Variable = 2,
        Method = 4,
        ObjectType = 8,
        VariableType = 16, // 0x00000010
        ReferenceType = 32, // 0x00000020
        DataType = 64, // 0x00000040
        View = 128, // 0x00000080
    }
}
