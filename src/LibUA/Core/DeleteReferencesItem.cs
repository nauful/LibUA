using System;

namespace LibUA
{
    namespace Core
    {
        public class DeleteReferencesItem
        {
            public NodeId SourceNodeId { get; set; }

            public NodeId ReferenceTypeId { get; set; }

            public Boolean IsForward { get; set; }

            public NodeId TargetNodeId { get; set; }

            public Boolean DeleteBidirectional { get; set; }
        }
    }
}
