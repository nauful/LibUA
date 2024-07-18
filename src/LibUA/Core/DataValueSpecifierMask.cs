using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum DataValueSpecifierMask
        {
            Value = 1 << 0,
            StatusCodeSpecified = 1 << 1,
            SourceTimestampSpecified = 1 << 2,
            ServerTimestampSpecified = 1 << 3,
            SourcePicosecondsSpecified = 1 << 4,
            ServerPicosecondsSpecified = 1 << 5,
        }
    }
}
