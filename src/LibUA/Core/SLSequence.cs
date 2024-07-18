namespace LibUA
{
    namespace Core
    {
        public class SLSequence
        {
            // UA_SecureConversationMessageHeader SecureConversationMessageHeader;
            // UA_SymmetricAlgorithmSecurityHeader SymmetricAlgorithmSecurityHeader;
            public uint SequenceNumber { get; set; }
            public uint RequestId { get; set; }
        }
    }
}
