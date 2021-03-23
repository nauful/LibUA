
// Type: LibUA.Core.EnumeratedTestType



using System;

namespace LibUA.Core
{
    [Flags]
    public enum EnumeratedTestType
    {
        Red = 1,
        Yellow = 4,
        Green = Yellow | Red, // 0x00000005
    }
}
