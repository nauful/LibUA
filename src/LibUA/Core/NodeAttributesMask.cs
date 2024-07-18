using System;

namespace LibUA
{
    namespace Core
    {
        [Flags]
        public enum NodeAttributesMask
        {
            None = 0x0,
            AccessLevel = 0x1,
            ArrayDimensions = 0x2,
            BrowseName = 0x4,
            ContainsNoLoops = 0x8,
            DataType = 0x10,
            Description = 0x20,
            DisplayName = 0x40,
            EventNotifier = 0x80,
            Executable = 0x100,
            Historizing = 0x200,
            InverseName = 0x400,
            IsAbstract = 0x800,
            MinimumSamplingInterval = 0x1000,
            NodeClass = 0x2000,
            NodeId = 0x4000,
            Symmetric = 0x8000,
            UserAccessLevel = 0x10000,
            UserExecutable = 0x20000,
            UserWriteMask = 0x40000,
            ValueRank = 0x80000,
            WriteMask = 0x100000,
            Value = 0x200000,
            All = 0x3FFFFF,
            BaseNode = 0x146064,
            Object = 0x1460E4,
            ObjectTypeOrDataType = 0x146864,
            Variable = 0x3D7277,
            VariableType = 0x3C6876,
            Method = 0x166164,
            ReferenceType = 0x14EC64,
            View = 0x1460EC,
        }
    }
}
