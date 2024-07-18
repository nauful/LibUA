using System;

namespace LibUA
{
    namespace Core
    {
        public class ResponseHeader
        {
            public DateTimeOffset Timestamp { get; set; }
            public uint RequestHandle { get; set; }
            public uint ServiceResult { get; set; }
            public byte ServiceDiagnosticsMask { get; set; }
            public string[] StringTable { get; set; }
            public ExtensionObject AdditionalHeader { get; set; }

            public ResponseHeader()
            {
            }

            public ResponseHeader(RequestHeader req)
            {
                Timestamp = req.Timestamp;
                RequestHandle = req.RequestHandle;
            }
        }
    }
}
