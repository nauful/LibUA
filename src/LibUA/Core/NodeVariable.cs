using System;

namespace LibUA
{
    namespace Core
    {
        public class NodeVariable : Node
        {
            public object Value
            {
                get; set;
            }

            public NodeId DataType
            {
                get; protected set;
            }

            public Core.AccessLevel AccessLevel
            {
                get; protected set;
            }

            public Core.AccessLevel UserAccessLevel
            {
                get; protected set;
            }

            public double MinimumResamplingInterval
            {
                get; protected set;
            }

            public bool IsHistorizing
            {
                get; protected set;
            }

            public int ValueRank
            {
                get; protected set;
            }

            public NodeVariable(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, Core.AccessLevel AccessLevel, Core.AccessLevel UserAccessLevel, double MinimumResamplingInterval, bool IsHistorizing, NodeId DataType, ValueRank DefaultRank = Core.ValueRank.Scalar)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.Value = null;
                this.DataType = DataType;
                this.ValueRank = (int)DefaultRank;

                this.AccessLevel = AccessLevel;
                this.UserAccessLevel = UserAccessLevel;
                this.MinimumResamplingInterval = MinimumResamplingInterval;
                this.IsHistorizing = IsHistorizing;
            }
        }
    }
}
