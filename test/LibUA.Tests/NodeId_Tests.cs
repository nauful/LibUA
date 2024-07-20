using LibUA.Core;

namespace LibUA.Tests
{
    public class NodeId_Tests
    {
        // OPC 10000-3: Address Space Model
        // 8.2.4 Identifier value
        // A canonical null NodeId has an IdType equal to Numeric, a NamespaceIndex equal to 0 and an
        // Identifier equal to 0.
        //
        // In addition to the canonical null NodeId the alternative values defined in Table 23 shall be
        // considered a null NodeId.
        // IdType        NamespaceIndex        Null Value
        // String           0                  A null or Empty String(“”)
        // Guid             0                  A Guid initialised with zeros(e.g. 00000000-0000-0000-0000-000000)
        // Opaque           0                  A null or Empty ByteString
        [Fact]
        public void NodeId_NullEquivalence()
        {
            NodeId nullNumeric = new NodeId(0, 0);
            NodeId nullString = new NodeId(0, null);
            NodeId emptyString = new NodeId(0, string.Empty);
            NodeId nullGuid = new NodeId(0, null, NodeIdNetType.Guid);
            NodeId emptyGuid = new NodeId(0, new Guid().ToByteArray(), NodeIdNetType.Guid);
            NodeId nullBytes = new NodeId(0, null, NodeIdNetType.ByteString);
            NodeId emptyBytes = new NodeId(0, new byte[0], NodeIdNetType.ByteString);

            Assert.Equal(nullNumeric, nullNumeric);
            Assert.Equal(nullNumeric, nullString);
            Assert.Equal(nullNumeric, emptyString);
            Assert.Equal(nullNumeric, nullGuid);
            Assert.Equal(nullNumeric, emptyGuid);
            Assert.Equal(nullNumeric, nullBytes);
            Assert.Equal(nullNumeric, emptyBytes);
        }

        [Fact]
        public void NodeId_NumericEquivalence()
        {
            Assert.Equal(new NodeId(2, 100), new NodeId(2, 100));
        }

        [Fact]
        public void NodeId_NumericConstEquivalence()
        {
            Assert.Equal(new NodeId(0, 2255), new NodeId(UAConst.Server_NamespaceArray));
        }

        [Fact]
        public void NodeId_NumericNamespaceNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, 100), new NodeId(3, 100));
        }

        [Fact]
        public void NodeId_NumericValueNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, 100), new NodeId(2, 101));
        }

        [Fact]
        public void NodeId_StringEquivalence()
        {
            Assert.Equal(new NodeId(2, "Test String"), new NodeId(2, "Test String"));
        }

        [Fact]
        public void NodeId_StringNamespaceNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, "Test String"), new NodeId(3, "Test String"));
        }

        [Fact]
        public void NodeId_StringValueNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, "Test String"), new NodeId(2, "Test String2"));
        }

        [Fact]
        public void NodeId_GuidEquivalence()
        {
            var guid = new Guid();
            var guid2 = new Guid(guid.ToByteArray());
            Assert.Equal(new NodeId(2, guid.ToByteArray(), NodeIdNetType.Guid), new NodeId(2, guid2.ToByteArray(), NodeIdNetType.Guid));
        }

        [Fact]
        public void NodeId_GuidNamespaceNonEquivalence()
        {
            var guid = new Guid();
            var guid2 = new Guid(guid.ToByteArray());
            Assert.NotEqual(new NodeId(2, guid.ToByteArray(), NodeIdNetType.Guid), new NodeId(3, guid2.ToByteArray(), NodeIdNetType.Guid));
        }

        [Fact]
        public void NodeId_GuidValueNonEquivalence()
        {
            var byteArray1 = Enumerable.Range(0, 16).Select(x => (byte)x).ToArray();
            var byteArray2 = Enumerable.Range(1, 16).Select(x => (byte)x).ToArray();
            var guid1 = new Guid(byteArray1);
            var guid2 = new Guid(byteArray2);
            Assert.NotEqual(new NodeId(2, guid1.ToByteArray(), NodeIdNetType.Guid), new NodeId(2, guid2.ToByteArray(), NodeIdNetType.Guid));
        }

        [Fact]
        public void NodeId_OpaqueEquivalence()
        {
            Assert.Equal(new NodeId(2, [0, 1, 2, 3, 4], NodeIdNetType.ByteString), new NodeId(2, [0, 1, 2, 3, 4], NodeIdNetType.ByteString));
        }

        [Fact]
        public void NodeId_OpaqueNamespaceNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, [0, 1, 2, 3, 4], NodeIdNetType.ByteString), new NodeId(3, [0, 1, 2, 3, 4], NodeIdNetType.ByteString));
        }

        [Fact]
        public void NodeId_OpaqueValueNonEquivalence()
        {
            Assert.NotEqual(new NodeId(2, [0, 1, 2, 3, 4], NodeIdNetType.ByteString), new NodeId(2, [0, 1, 2, 3, 5], NodeIdNetType.ByteString));
        }
    }
}
