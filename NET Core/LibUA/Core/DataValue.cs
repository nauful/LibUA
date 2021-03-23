
// Type: LibUA.Core.DataValue



using System;

namespace LibUA.Core
{
    public class DataValue
    {
        public object Value { get; protected set; }

        public uint? StatusCode { get; protected set; }

        public DateTime? SourceTimestamp { get; protected set; }

        public DateTime? ServerTimestamp { get; set; }

        public DataValue(
          object Value = null,
          uint? StatusCode = null,
          DateTime? SourceTimestamp = null,
          DateTime? ServerTimestamp = null)
        {
            this.Value = Value;
            this.StatusCode = StatusCode;
            this.SourceTimestamp = SourceTimestamp;
            this.ServerTimestamp = ServerTimestamp;
        }

        public DataValue(
          object Value,
          LibUA.Core.StatusCode? StatusCode,
          DateTime? SourceTimestamp = null,
          DateTime? ServerTimestamp = null)
        {
            this.Value = Value;
            this.StatusCode = StatusCode.HasValue ? new uint?((uint)StatusCode.Value) : new uint?();
            this.SourceTimestamp = SourceTimestamp;
            this.ServerTimestamp = ServerTimestamp;
        }

        public byte GetEncodingMask()
        {
            byte num = 0;
            if (this.Value != null)
            {
                num |= 1;
            }

            if (this.StatusCode.HasValue)
            {
                num |= 2;
            }

            if (this.SourceTimestamp.HasValue)
            {
                num |= 4;
            }

            if (this.ServerTimestamp.HasValue)
            {
                num |= 8;
            }

            return num;
        }
    }
}
