
// Type: LibUA.Core.EventNotification



namespace LibUA.Core
{
    public class EventNotification
    {
        public EventNotification.Field[] Fields { get; set; }

        public EventNotification(EventNotification.Field[] Fields)
        {
            this.Fields = Fields;
        }

        public class Field
        {
            public SimpleAttributeOperand Operand;
            public object Value;
        }
    }
}
