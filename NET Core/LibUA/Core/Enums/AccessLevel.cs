
// Type: LibUA.Core.AccessLevel



using System;

namespace LibUA.Core
{
    [Flags]
    public enum AccessLevel
    {
        CurrentRead = 1,
        CurrentWrite = 2,
        HistoryRead = 4,
        HistoryWrite = 8,
    }
}
