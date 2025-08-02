using LibUA.Core;

namespace LibUA.Tests
{
    public class NodeIdTests
    {
        // OPC 10000-3: Address Space Model
        // 8.2.4 Identifier value
        // A canonical null NodeId has an IdType equal to Numeric, a NamespaceIndex equal to 0 and an
        // Identifier equal to 0.
        //
        // In addition to the canonical null NodeId the alternative values defined in Table 23 shall be
        // considered a null NodeId.
        // IdType        NamespaceIndex        Null Value
        // String           0                  A null or Empty String("")
        // Guid             0                  A Guid initialised with zeros(e.g. 00000000-0000-0000-0000-000000)
        // Opaque           0                  A null or Empty ByteString
        [Fact]
        public void NodeId_NullEquivalence()
        {
            NodeId nullNumeric = new(0, 0);
            NodeId nullString = new(0, null);
            NodeId emptyString = new(0, string.Empty);
            NodeId nullGuid = new(0, null, NodeIdNetType.Guid);
            NodeId emptyGuid = new(0, new Guid().ToByteArray(), NodeIdNetType.Guid);
            NodeId nullBytes = new(0, null, NodeIdNetType.ByteString);
            NodeId emptyBytes = new(0, [], NodeIdNetType.ByteString);

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

        [Fact]
        public void NodeId_TryParse_Numeric()
        {
            var nodeId = NodeId.TryParse("ns=2;i=100");
            Assert.NotNull(nodeId);
            Assert.Equal(2, nodeId.NamespaceIndex);
            Assert.Equal(100u, nodeId.NumericIdentifier);
            Assert.Equal(NodeIdNetType.Numeric, nodeId.IdType);
        }

        [Fact]
        public void NodeId_TryParse_String()
        {
            var nodeId = NodeId.TryParse("ns=2;s=TestString");
            Assert.NotNull(nodeId);
            Assert.Equal(2, nodeId.NamespaceIndex);
            Assert.Equal("TestString", nodeId.StringIdentifier);
            Assert.Equal(NodeIdNetType.String, nodeId.IdType);
        }

        [Fact]
        public void NodeId_TryParse_OpaqueBase64()
        {
            var nodeId = NodeId.TryParse("ns=2;b=VEVTVHRlc3RURVNU");
            Assert.NotNull(nodeId);
            Assert.Equal("ns=2;b=VEVTVHRlc3RURVNU", nodeId.ToString());
            Assert.Equal(2, nodeId.NamespaceIndex);
            Assert.Equal(Convert.FromBase64String("VEVTVHRlc3RURVNU"), nodeId.ByteStringIdentifier);
            Assert.Equal(NodeIdNetType.ByteString, nodeId.IdType);
        }

        [Fact]
        public void NodeId_TryParse_Guid()
        {
            var guid = Guid.NewGuid();
            var nodeId = NodeId.TryParse($"ns=2;g={guid}");
            Assert.NotNull(nodeId);
            Assert.Equal($"ns=2;g={guid}", nodeId.ToString());
            Assert.Equal(2, nodeId.NamespaceIndex);
            Assert.Equal(guid.ToByteArray(), nodeId.ByteStringIdentifier);
            Assert.Equal(NodeIdNetType.Guid, nodeId.IdType);
        }

        [Fact]
        public void NodeId_TryParse_DefaultNamespace()
        {
            var guid = Guid.NewGuid();
            var nodeId = NodeId.TryParse($"g={guid}");
            var expected = new NodeId(0, guid);
            Assert.NotNull(nodeId);
            Assert.Equal(expected, nodeId);
        }

        [Fact]
        public void NodeId_ToString_DefaultNamespace()
        {
            var guid = Guid.NewGuid();
            var nodeId = new NodeId(0, guid);
            Assert.Equal($"g={guid}", nodeId.ToString());
        }

        [Fact]
        public void NodeId_TryParse_OpcExamples()
        {
            var nodeIdA = NodeId.TryParse("i=13");
            Assert.NotNull(nodeIdA);
            Assert.Equal(NodeIdNetType.Numeric, nodeIdA.IdType);
            Assert.Equal(0u, nodeIdA.NamespaceIndex);
            Assert.Equal(13u, nodeIdA.NumericIdentifier);

            var nodeIdB = NodeId.TryParse("ns=10;i=12345");
            Assert.NotNull(nodeIdB);
            Assert.Equal(NodeIdNetType.Numeric, nodeIdB.IdType);
            Assert.Equal(10u, nodeIdB.NamespaceIndex);
            Assert.Equal(12345u, nodeIdB.NumericIdentifier);

            // TODO: Support nsu= format for NodeId
            //var nodeIdC = NodeId.TryParse("nsu=http://widgets.com/schemas/hello;s=水 World");
            //Assert.NotNull(nodeIdC);
            //Assert.Equal(NodeIdNetType.String, nodeIdC.IdType);
            //Assert.Equal(10u, nodeIdC.NamespaceIndex);
            //Assert.Equal("水 World", nodeIdC.StringIdentifier);

            var nodeIdD = NodeId.TryParse("g=09087e75-8e5e-499b-954f-f2a9603db28a");
            Assert.NotNull(nodeIdD);
            Assert.Equal(NodeIdNetType.Guid, nodeIdD.IdType);
            Assert.Equal(0u, nodeIdD.NamespaceIndex);
            Assert.Equal(new Guid("09087e75-8e5e-499b-954f-f2a9603db28a").ToByteArray(), nodeIdD.ByteStringIdentifier);

            // TODO: Support nsu= format for NodeId
            //var nodeIdE = NodeId.TryParse("nsu=tag:acme.com,2023:schemas:data#off%3B;b=M/RbKBsRVkePCePcx24oRA==");
            //Assert.NotNull(nodeIdE);
            //Assert.Equal(NodeIdNetType.ByteString, nodeIdE.IdType);
            //Assert.Equal(10u, nodeIdE.NamespaceIndex);
            //Assert.Equal(Convert.FromBase64String("M/RbKBsRVkePCePcx24oRA=="), nodeIdE.ByteStringIdentifier);
        }
    }
}
