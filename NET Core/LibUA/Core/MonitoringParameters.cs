
// Type: LibUA.Core.MonitoringParameters



namespace LibUA.Core
{
    public class MonitoringParameters
    {
        public uint ClientHandle { get; protected set; }

        public double SamplingInterval { get; protected set; }

        public EventFilter Filter { get; protected set; }

        public uint QueueSize { get; protected set; }

        public bool DiscardOldest { get; protected set; }

        public MonitoringParameters(
          uint ClientHandle,
          double SamplingInterval,
          EventFilter Filter,
          uint QueueSize,
          bool DiscardOldest)
        {
            this.ClientHandle = ClientHandle;
            this.SamplingInterval = SamplingInterval;
            this.Filter = Filter;
            this.QueueSize = QueueSize;
            this.DiscardOldest = DiscardOldest;
        }
    }
}
