using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace LibUA
{
    public class NetworkStreamWithSocket : NetworkStream
    {
        public NetworkStreamWithSocket(Socket socket) : base(socket) { }
        public NetworkStreamWithSocket(Socket socket, bool ownsSocket) : base(socket, ownsSocket) { }
        public NetworkStreamWithSocket(Socket socket, FileAccess access) : base(socket, access) { }
        public NetworkStreamWithSocket(Socket socket, FileAccess access, bool ownsSocket) : base(socket, access, ownsSocket) { }

        public Socket _Socket { get => base.Socket; }
    }
}
