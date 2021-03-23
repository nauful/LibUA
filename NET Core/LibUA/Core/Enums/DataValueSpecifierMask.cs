
// Type: LibUA.Core.DataValueSpecifierMask



using System;

namespace LibUA.Core
{
    [Flags]
    public enum DataValueSpecifierMask
    {
        Value = 1,
        StatusCodeSpecified = 2,
        SourceTimestampSpecified = 4,
        ServerTimestampSpecified = 8,
        SourcePicosecondsSpecified = 16, // 0x00000010
        ServerPicosecondsSpecified = 32, // 0x00000020
    }
}
