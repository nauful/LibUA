namespace LibUA
{
    namespace Core
    {
        public class ExtensionObject<TPayload> : ExtensionObject
        {
            public TPayload Value
            {
                get
                {
                    if (Payload != null && Payload is TPayload tPayload)
                        return tPayload;
                    return default;
                }
                set => Payload = value;
            }
        }
    }
}
