using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum OpenFileType
        {
            Read = 0x1,
            Write = 0x2,
            EraseExisting = 0x4,
            Append = 0x8,
        }
    }
}
