namespace LibUA
{
    namespace Core
    {
        public enum MessageType : uint
        {
            Hello = 0x4C4548,
            Acknowledge = 0x4B4341,
            Error = 0x525245,
            Open = 0x4E504F,
            Message = 0x47534D,
            Close = 0x4F4C43,
        }
    }
}
