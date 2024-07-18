using System;

namespace LibUA
{
    namespace Core
    {
        public class AddReferencesItem
        {
            public NodeId SourceNodeId { get; set; }

            public NodeId ReferenceTypeId { get; set; }

            public Boolean IsForward { get; set; }

            public String TargetServerUri { get; set; }

            public NodeId TargetNodeId { get; set; }

            public NodeClass TargetNodeClass { get; set; }
        }
    }
}
