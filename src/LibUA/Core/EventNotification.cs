namespace LibUA
{
    namespace Core
    {
        public class EventNotification
        {
            public class Field
            {
                public SimpleAttributeOperand Operand;
                public object Value;
            }

            public Field[] Fields { get; set; }

            public EventNotification(Field[] Fields)
            {
                this.Fields = Fields;
            }
        }
    }
}
