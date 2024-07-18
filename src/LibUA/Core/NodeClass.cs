using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum NodeClass
        {
            Unspecified = 0x0,
            Object = 0x1,
            Variable = 0x2,
            Method = 0x4,
            ObjectType = 0x8,
            VariableType = 0x10,
            ReferenceType = 0x20,
            DataType = 0x40,
            View = 0x80,
        }
    }
}
