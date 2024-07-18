using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum EnumeratedTestType
        {
            Red = 0x1,
            Yellow = 0x4,
            Green = 0x5,
        }
    }
}
