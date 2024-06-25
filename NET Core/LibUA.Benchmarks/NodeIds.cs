using BenchmarkDotNet.Attributes;
using LibUA.Core;

namespace LibUA.Benchmarks
{
    [MarkdownExporter]
    [MemoryDiagnoser(false)]
    public class NodeId_Benchmarks
    {
        public readonly static NodeId[] NullNodes =
        [
            new NodeId(0,0),
            new NodeId(0, null, NodeIdNetType.String),
            new NodeId(0, string.Empty),
            new NodeId(0, null, NodeIdNetType.Guid),
            new NodeId(0, Guid.Empty.ToByteArray(), NodeIdNetType.Guid),
            new NodeId(0, null, NodeIdNetType.ByteString),
            new NodeId(0, [], NodeIdNetType.ByteString)
        ];

        public readonly static NodeId[] NumericNodes =
        [
            new NodeId(2, 1),
            new NodeId(2, 100),
            new NodeId(2, 200),
            new NodeId(2, 300),
            new NodeId(2, 400),
            new NodeId(2, 500),
            new NodeId(2, 600),
            new NodeId(2, 700),
            new NodeId(2, 800),
            new NodeId(2, 900),
            new NodeId(2, 1000),
        ];

        public readonly static NodeId[] StringNodes =
        [
            new NodeId(2, "Test String 1"),
            new NodeId(2, "Test String 2"),
            new NodeId(2, "Test String 3"),
            new NodeId(2, "Test String 4"),
            new NodeId(2, "Test String 5"),
            new NodeId(2, "Test String 6"),
            new NodeId(2, "Test String 7"),
            new NodeId(2, "Test String 8"),
            new NodeId(2, "Test String 9"),
            new NodeId(2, "Test String 10"),
        ];

        public readonly static NodeId[] GuidNodes =
        [
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
            new NodeId(2, new Guid().ToByteArray(), NodeIdNetType.Guid),
        ];

        public readonly static NodeId[] ByteStringNodes =
        [
            new NodeId(2, new byte[] { 0, 1, 2, 3 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 2, 1, 2, 3 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 3, 2, 3 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 1, 2, 1 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 6, 2, 3, 7, 5, 6, 4, 255 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 1, 8, 3 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 9, 2, 3 }, NodeIdNetType.Guid),
            new NodeId(2, new byte[] { 0, 1, 2, 0, 1, 5, 6, 7 }, NodeIdNetType.Guid),
        ];

        public readonly static NodeId[] Nodes =
        [
            .. NullNodes,
            .. StringNodes,
            .. GuidNodes,
            .. ByteStringNodes
        ];


        [Benchmark]
        public void NodeIdEquivalency()
        {
            for(int i = 0; i < Nodes.Length; i++)
            {
                for(int j = 0; j < Nodes.Length; j++)
                {
                    _ = Nodes[i].Equals(Nodes[j]);
                }
            }
        }

        [Benchmark]
        public void NodeIdAllocations()
        {
            NodeId[] nodes = new NodeId[1_000_000];
            for (int i = 0; i < 1_000_000; i++)
            {
                nodes[i] = new NodeId(0, 0);
            }
        }
    }
}
