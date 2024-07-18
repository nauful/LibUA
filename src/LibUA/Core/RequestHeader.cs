using System;

namespace LibUA
{
    namespace Core
    {
        public class RequestHeader
        {
            public NodeId AuthToken { get; set; }
            public DateTime Timestamp { get; set; }
            public uint RequestHandle { get; set; }
            public uint ReturnDiagnostics { get; set; }
            public string AuditEntryId { get; set; }
            public uint TimeoutHint { get; set; }
            public ExtensionObject AdditionalHeader { get; set; }

            // Current parameters at receive time
            public uint SecurityRequestID { get; set; }
            public uint SecuritySequenceNum { get; set; }
            public uint SecurityTokenID { get; set; }
        }
    }
}
