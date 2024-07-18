using System;

namespace LibUA
{
    namespace Core
    {
        public class DataValue
        {
            public object Value { get; set; }
            public uint? StatusCode { get; set; }
            public DateTime? SourceTimestamp { get; set; }
            public DateTime? ServerTimestamp { get; set; }

            public DataValue(object Value = null, uint? StatusCode = null, DateTime? SourceTimestamp = null, DateTime? ServerTimestamp = null)
            {
                this.Value = Value;
                this.StatusCode = StatusCode;
                this.SourceTimestamp = SourceTimestamp;
                this.ServerTimestamp = ServerTimestamp;
            }

            public DataValue(object Value, StatusCode? StatusCode, DateTime? SourceTimestamp = null, DateTime? ServerTimestamp = null)
            {
                this.Value = Value;
                this.StatusCode = StatusCode.HasValue ? (uint?)StatusCode.Value : null;
                this.SourceTimestamp = SourceTimestamp;
                this.ServerTimestamp = ServerTimestamp;
            }

            public byte GetEncodingMask()
            {
                byte res = 0;

                if (Value != null) { res |= (byte)DataValueSpecifierMask.Value; }
                if (StatusCode != null) { res |= (byte)DataValueSpecifierMask.StatusCodeSpecified; }
                if (SourceTimestamp != null) { res |= (byte)DataValueSpecifierMask.SourceTimestampSpecified; }
                if (ServerTimestamp != null) { res |= (byte)DataValueSpecifierMask.ServerTimestampSpecified; }

                return res;
            }
        }
    }
}
