using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum AccessLevel
        {
            CurrentRead = 0x1,
            CurrentWrite = 0x2,
            HistoryRead = 0x4,
            HistoryWrite = 0x8,
        }
    }
}
