
// Type: LibUA.Core.OpenFileType



using System;

namespace LibUA.Core
{
    [Flags]
    public enum OpenFileType
    {
        Read = 1,
        Write = 2,
        EraseExisiting = 4,
        Append = 8,
    }
}
