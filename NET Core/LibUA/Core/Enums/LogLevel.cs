
// Type: LibUA.LogLevel



using System;

namespace LibUA
{
    [Flags]
    public enum LogLevel
    {
        None = 0,
        Info = 1,
        Warn = 2,
        Error = 4,
    }
}
