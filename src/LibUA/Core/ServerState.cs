namespace LibUA
{
    namespace Core
    {
        public enum ServerState
        {
            Running = 0,
            Failed = 1,
            NoConfiguration = 2,
            Suspended = 3,
            Shutdown = 4,
            Test = 5,
            CommunicationFault = 6,
            Unknown = 7,
        }
    }
}
