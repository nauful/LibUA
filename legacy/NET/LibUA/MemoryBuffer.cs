using System;

namespace LibUA
{
    namespace Core
    {
        public class MemoryBuffer
        {
            public bool IsReadOnly { get; protected set; }

            private int position = 0;
            public int Position
            {
                get { return position; }
                set
                {
                    position = value;

                    if (position < 0 || position > Capacity)
                    {
                        throw new Exception(string.Format("Position {0} is out of range [0, {1}]", position, Capacity));
                    }
                }
            }

            public int Capacity { get; protected set; }
            public int Allocated { get; protected set; }
            public bool IsFixedCapacity { get; protected set; }

            public byte[] Buffer { get; protected set; }

            public ArraySegment<byte> AsArraySegmentToPosition()
            {
                return new ArraySegment<byte>(Buffer, 0, Position);
            }

            public ArraySegment<byte> AsArraySegmentToCapacity()
            {
                return new ArraySegment<byte>(Buffer, 0, Capacity);
            }

            public ArraySegment<byte> AsArraySegmentPositionToCapacity()
            {
                return new ArraySegment<byte>(Buffer, Position, Capacity - Position);
            }

            public bool RestrictCapacity(int newCapacity)
            {
                if (newCapacity <= 0) { newCapacity = 0; }

                if (newCapacity > Capacity)
                {
                    return false;
                }

                Capacity = newCapacity;
                return true;
            }

            public MemoryBuffer()
            {
                Position = Capacity = Allocated = 0;
                Buffer = null;
            }

            public MemoryBuffer(byte[] Src)
            {
                Position = 0;
                IsReadOnly = true;

                if (Src == null)
                {
                    Capacity = Allocated = 0;
                }
                else
                {
                    Capacity = Allocated = Src.Length;
                    this.Buffer = Src;
                }
            }

            public MemoryBuffer(byte[] Src, int SrcLength)
            {
                Position = 0;
                IsReadOnly = true;

                if (Src == null)
                {
                    Capacity = Allocated = 0;
                }
                else
                {
                    if (SrcLength > Src.Length) { SrcLength = Src.Length; }

                    Capacity = Allocated = SrcLength;
                    this.Buffer = Src;
                }
            }

            public MemoryBuffer(int Size)
            {
                Position = 0;
                IsReadOnly = false;
                IsFixedCapacity = true;

                Buffer = new byte[Size];
                Capacity = Allocated = Size;
            }

            public bool EnsureAvailable(int Length, bool readOnly)
            {
                if (readOnly)
                {
                    return Position + Length <= Capacity;
                }

                int NewCapacity = Position + Length;
                if (NewCapacity <= Capacity)
                {
                    return true;
                }

                if (IsFixedCapacity && NewCapacity > Capacity)
                {
                    return false;
                }

                if (Allocated >= NewCapacity)
                {
                    Capacity = NewCapacity;
                    return true;
                }

                try
                {
                    int newAllocated = Math.Max(NewCapacity, Math.Max(256, (int)(1.5 * Allocated)));
                    var newBuffer = new byte[newAllocated];
                    if (Buffer != null)
                    {
                        Array.Copy(Buffer, newBuffer, Math.Min(Capacity, NewCapacity));
                    }

                    Buffer = newBuffer;
                    Allocated = newAllocated;
                }
                catch
                {
                    return false;
                }

                Capacity = NewCapacity;
                return true;
            }

            public void Rewind()
            {
                Position = 0;
            }

            public bool Append(byte[] Add)
            {
                return Append(Add, Add.Length);
            }

            public bool Append(byte[] Add, int Size)
            {
                if (Add == null || Size > Add.Length)
                {
                    return false;
                }

                if (Size == 0)
                {
                    return true;
                }

                if (!EnsureAvailable(Size, false))
                {
                    return false;
                }

                Array.Copy(Add, 0, Buffer, Position, Size);
                Position += Size;

                return true;
            }

            public bool Append(byte[] Add, int Offset, int Size)
            {
                if (Add == null || Size > Add.Length - Offset)
                {
                    return false;
                }

                if (Size == 0)
                {
                    return true;
                }

                if (!EnsureAvailable(Size, false))
                {
                    return false;
                }

                Array.Copy(Add, Offset, Buffer, Position, Size);
                Position += Size;

                return true;
            }

            public bool Read(byte[] Dest, int Size)
            {
                if (!EnsureAvailable(Size, true)) { return false; }

                Array.Copy(Buffer, Position, Dest, 0, Size);
                Position += Size;

                return true;
            }

            public bool Prepend(byte[] Add, int Size)
            {
                if (Add == null || Size > Add.Length)
                {
                    return false;
                }

                if (Size == 0)
                {
                    return true;
                }

                if (!EnsureAvailable(Size, false))
                {
                    return false;
                }

                var tmp = new byte[Position];
                if (Position > 0)
                {
                    Array.Copy(Buffer, tmp, Position);
                }

                Array.Copy(Add, Buffer, Size);

                if (Position > 0)
                {
                    Array.Copy(tmp, 0, Buffer, Size, Position);
                }

                Position += Size;

                return true;
            }

            public bool Append(MemoryBuffer Mem)
            {
                return Append(Mem.Buffer, Mem.Capacity);
            }

            public bool Encode(byte v)
            {
                if (!EnsureAvailable(1, false)) { return false; }
                Buffer[Position++] = v;
                return true;
            }

            public bool Decode(out byte v)
            {
                v = 0;
                if (!EnsureAvailable(1, true)) { return false; }

                v = Buffer[Position++];
                return true;
            }

            public bool Encode(bool v)
            {
                return Encode((byte)(v ? 1 : 0));
            }

            public bool Decode(out bool v)
            {
                v = false;
                if (!Decode(out byte b)) { return false; }
                v = b != 0;

                return true;
            }

            public bool Encode(SByte v)
            {
                return Encode((byte)v);
            }

            public bool Decode(out SByte v)
            {
                v = 0;
                if (!Decode(out byte b)) { return false; }
                v = (SByte)b;

                return true;
            }

            public bool Encode(UInt16 v)
            {
                if (!EnsureAvailable(2, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Position += 2;
                return true;
            }

            public bool Decode(out UInt16 v)
            {
                v = 0;
                if (!EnsureAvailable(2, true)) { return false; }

                v = (UInt16)Buffer[Position];
                v += (UInt16)(Buffer[Position + 1] << 8);
                Position += 2;
                return true;
            }

            public bool Encode(Int16 v)
            {
                if (!EnsureAvailable(2, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Position += 2;
                return true;
            }

            public bool Decode(out Int16 v)
            {
                v = 0;
                if (!EnsureAvailable(2, true)) { return false; }

                v = (Int16)Buffer[Position];
                v += (Int16)(Buffer[Position + 1] << 8);
                Position += 2;
                return true;
            }

            public bool Encode(UInt32 v)
            {
                if (!EnsureAvailable(4, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Buffer[Position + 2] = (byte)((v >> 16) & 0xFF);
                Buffer[Position + 3] = (byte)((v >> 24) & 0xFF);
                Position += 4;
                return true;
            }

            public bool Encode(UInt32 v, int pos)
            {
                var restorePos = Position;

                Position = pos;
                if (!EnsureAvailable(4, false))
                {
                    Position = restorePos; return false;
                }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Buffer[Position + 2] = (byte)((v >> 16) & 0xFF);
                Buffer[Position + 3] = (byte)((v >> 24) & 0xFF);
                Position = restorePos;

                return true;
            }

            public bool Decode(out UInt32 v)
            {
                v = 0;
                if (!EnsureAvailable(4, true)) { return false; }

                v = (UInt32)Buffer[Position];
                v += (UInt32)(Buffer[Position + 1] << 8);
                v += (UInt32)(Buffer[Position + 2] << 16);
                v += (UInt32)(Buffer[Position + 3] << 24);
                Position += 4;
                return true;
            }

            public bool DecodeArraySize(out UInt32 v)
            {
                if (!Decode(out v))
                {
                    return false;
                }

                // Array length of -1 == no array encoded
                if (v == 0xFFFFFFFFu)
                {
                    v = 0;
                }

                return true;
            }

            public bool Decode(out UInt32 v, int pos)
            {
                v = 0;
                if (pos + 4 > Buffer.Length) { return false; }

                v = (UInt32)Buffer[pos];
                v += (UInt32)(Buffer[pos + 1] << 8);
                v += (UInt32)(Buffer[pos + 2] << 16);
                v += (UInt32)(Buffer[pos + 3] << 24);

                return true;
            }

            public bool Encode(Int32 v)
            {
                if (!EnsureAvailable(4, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Buffer[Position + 2] = (byte)((v >> 16) & 0xFF);
                Buffer[Position + 3] = (byte)((v >> 24) & 0xFF);
                Position += 4;
                return true;
            }

            public bool Decode(out Int32 v)
            {
                v = 0;
                if (!EnsureAvailable(4, true)) { return false; }

                v = (Int32)Buffer[Position];
                v += (Int32)(Buffer[Position + 1] << 8);
                v += (Int32)(Buffer[Position + 2] << 16);
                v += (Int32)(Buffer[Position + 3] << 24);
                Position += 4;
                return true;
            }

            public bool Encode(UInt64 v)
            {
                if (!EnsureAvailable(8, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Buffer[Position + 2] = (byte)((v >> 16) & 0xFF);
                Buffer[Position + 3] = (byte)((v >> 24) & 0xFF);

                Buffer[Position + 4] = (byte)((v >> 32) & 0xFF);
                Buffer[Position + 5] = (byte)((v >> 40) & 0xFF);
                Buffer[Position + 6] = (byte)((v >> 48) & 0xFF);
                Buffer[Position + 7] = (byte)((v >> 56) & 0xFF);
                Position += 8;
                return true;
            }

            public bool Decode(out UInt64 v)
            {
                v = 0;
                if (!EnsureAvailable(8, true)) { return false; }

                v = (UInt64)Buffer[Position];
                v += ((UInt64)Buffer[Position + 1] << 8);
                v += ((UInt64)Buffer[Position + 2] << 16);
                v += ((UInt64)Buffer[Position + 3] << 24);

                v += ((UInt64)Buffer[Position + 4] << 32);
                v += ((UInt64)Buffer[Position + 5] << 40);
                v += ((UInt64)Buffer[Position + 6] << 48);
                v += ((UInt64)Buffer[Position + 7] << 56);
                Position += 8;
                return true;
            }

            public bool Encode(Int64 v)
            {
                if (!EnsureAvailable(8, false)) { return false; }

                Buffer[Position] = (byte)(v & 0xFF);
                Buffer[Position + 1] = (byte)((v >> 8) & 0xFF);
                Buffer[Position + 2] = (byte)((v >> 16) & 0xFF);
                Buffer[Position + 3] = (byte)((v >> 24) & 0xFF);

                Buffer[Position + 4] = (byte)((v >> 32) & 0xFF);
                Buffer[Position + 5] = (byte)((v >> 40) & 0xFF);
                Buffer[Position + 6] = (byte)((v >> 48) & 0xFF);
                Buffer[Position + 7] = (byte)((v >> 56) & 0xFF);
                Position += 8;
                return true;
            }

            public bool Decode(out Int64 v)
            {
                v = 0;
                if (!EnsureAvailable(8, true)) { return false; }

                v = (Int64)Buffer[Position];
                v += ((Int64)Buffer[Position + 1] << 8);
                v += ((Int64)Buffer[Position + 2] << 16);
                v += ((Int64)Buffer[Position + 3] << 24);

                v += ((Int64)Buffer[Position + 4] << 32);
                v += ((Int64)Buffer[Position + 5] << 40);
                v += ((Int64)Buffer[Position + 6] << 48);
                v += ((Int64)Buffer[Position + 7] << 56);
                Position += 8;
                return true;
            }

            public unsafe bool Encode(Single v)
            {
                return Encode(*(UInt32*)&v);
            }

            public unsafe bool Decode(out Single v)
            {
                v = 0;
                if (!Decode(out uint i)) { return false; }
                v = *(Single*)&i;
                return true;
            }

            public unsafe bool Encode(Double v)
            {
                return Encode(*(UInt64*)&v);
            }

            public unsafe bool Decode(out Double v)
            {
                v = 0;
                if (!Decode(out ulong i)) { return false; }
                v = *(Double*)&i;
                return true;
            }

            public int VarLenU32Decode(out UInt32 v)
            {
                int len = Capacity - Position;

                int bufLen = len > 8 ? 8 : (int)len;

                var tmp = new byte[bufLen];
                if (bufLen > 0)
                {
                    Array.Copy(Buffer, Position, tmp, 0, bufLen);
                }

                int adv = Coding.VarLenU32Decode(out v, tmp);
                if (adv > 0)
                {
                    Position += adv;
                }

                return adv;
            }

            public int VarLenU32Encode(UInt32 v)
            {
                var buffer = new byte[8];

                int adv = Coding.VarLenU32Encode(v, buffer);
                if (adv > 0)
                {
                    Append(buffer, adv);
                }

                return adv;
            }

            public bool VariantEncode(object obj)
            {
                int rank = 0;
                VariantType varType;
                if (obj is Array && !(obj is byte[]))
                {
                    var type = obj.GetType();
                    rank = type.GetArrayRank();
                    type = type.GetElementType();

                    varType = Coding.GetVariantTypeFromType(type);
                }
                else
                {
                    varType = Coding.GetVariantTypeFromInstance(obj);
                }

                byte mask = (byte)varType;

                if (rank > 1)
                {
                    mask |= 0x40;
                }

                if (rank >= 1)
                {
                    mask |= 0x80;
                    if (!Encode(mask)) { return false; }

                    var arr = obj as Array;

                    if (!Encode((int)(arr.Length))) { return false; }
                    foreach (var value in arr)
                    {
                        if (!VariantEncode(value, mask))
                        {
                            return false;
                        }
                    }

                    if (rank > 1)
                    {
                        if (!Encode((int)rank)) { return false; }
                        for (int i = 0; i < rank; i++)
                        {
                            int dimension = arr.GetLength(i);
                            if (!Encode(dimension)) { return false; }
                        }
                    }
                }
                else
                {
                    if (!Encode(mask)) { return false; }
                    if (!VariantEncode(obj, mask))
                    {
                        return false;
                    }
                }

                return true;
            }

            public bool VariantDecode(out object res)
            {
                res = null;

                if (!Decode(out byte mask))
                {
                    return false;
                }

                if ((mask & 0x80) != 0)
                {
                    if (!Decode(out int arrLen)) { return false; }
                    if (arrLen < 0) { return false; }

                    Type type = Coding.GetNetType((VariantType)(mask & 0x3F));

                    var arr = Array.CreateInstance(type, arrLen);
                    for (int i = 0; i < arrLen; i++)
                    {
                        if (!VariantDecode(out object v, mask))
                        {
                            return false;
                        }

                        arr.SetValue(v, i);
                    }

                    res = arr;

                    // Decoding multidimensional arrays is not supported, decode as a flat array.
                    if ((mask & 0x40) != 0)
                    {
                        if (!Decode(out int rank)) { return false; }

                        for (int i = 0; i < rank; i++)
                        {
                            if (!Decode(out int _)) { return false; }
                        }
                    }
                }
                else
                {
                    if (!VariantDecode(out res, mask))
                    {
                        return false;
                    }
                }

                return true;
            }

            public bool VariantEncode(object obj, byte mask)
            {
                switch (mask & 0x3F)
                {
                    case (int)VariantType.Null: return true;
                    case (int)VariantType.Boolean: return Encode((bool)obj);
                    case (int)VariantType.SByte: return Encode((SByte)obj);
                    case (int)VariantType.Byte: return Encode((Byte)obj);
                    case (int)VariantType.Int16: return Encode((Int16)obj);
                    case (int)VariantType.UInt16: return Encode((UInt16)obj);
                    case (int)VariantType.Int32: return Encode((Int32)obj);
                    case (int)VariantType.UInt32: return Encode((UInt32)obj);
                    case (int)VariantType.Int64: return Encode((Int64)obj);
                    case (int)VariantType.UInt64: return Encode((UInt64)obj);
                    case (int)VariantType.Float: return Encode((Single)obj);
                    case (int)VariantType.Double: return Encode((Double)obj);
                    case (int)VariantType.String: return this.EncodeUAString((string)obj);
                    case (int)VariantType.DateTime: return Encode((Int64)((DateTime)obj).ToFileTimeUtc());
                    //case (int)VariantType.Guid: return Encode((int)obj);
                    case (int)VariantType.ByteString: return this.EncodeUAByteString((byte[])obj);
                    //case (int)VariantType.XmlElement: return Encode((int)obj);
                    case (int)VariantType.NodeId: return this.Encode((NodeId)obj);
                    //case (int)VariantType.ExpandedNodeId: return Encode((int)obj);
                    case (int)VariantType.StatusCode: return Encode((UInt32)obj);
                    case (int)VariantType.QualifiedName: return this.Encode((QualifiedName)obj);
                    case (int)VariantType.LocalizedText: return this.Encode((LocalizedText)obj);
                    case (int)VariantType.ExtensionObject: return this.Encode((ExtensionObject)obj);
                    //case (int)VariantType.DataValue: return Encode((int)obj);
                    //case (int)VariantType.Variant: return Encode((int)obj);
                    //case (int)VariantType.DiagnosticInfo: return Encode((int)obj);
                    default:
                        throw new Exception("TODO");
                }
            }

            public bool VariantDecode(out object obj, byte mask)
            {
                obj = null;

                switch (mask & 0x3F)
                {
                    case (int)VariantType.Null:
                    case (int)VariantType.Boolean: { if (!Decode(out bool v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.SByte: { if (!Decode(out sbyte v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Byte: { if (!Decode(out byte v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Int16: { if (!Decode(out short v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.UInt16: { if (!Decode(out ushort v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Int32: { if (!Decode(out int v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.UInt32: { if (!Decode(out uint v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Int64: { if (!Decode(out long v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.UInt64: { if (!Decode(out ulong v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Float: { if (!Decode(out float v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.Double: { if (!Decode(out double v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.String: { if (!this.DecodeUAString(out string v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.DateTime: { if (!Decode(out long v)) { return false; } obj = DateTime.FromFileTimeUtc(v); return true; ; }
                    //case (int)VariantType.Guid: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    case (int)VariantType.ByteString: { if (!this.DecodeUAByteString(out byte[] v)) { return false; } obj = v; return true; ; }
                    //case (int)VariantType.XmlElement: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    case (int)VariantType.NodeId: { if (!this.Decode(out NodeId v)) { return false; } obj = v; return true; ; }
                    //case (int)VariantType.ExpandedNodeId: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    case (int)VariantType.StatusCode: { if (!Decode(out uint v)) { return false; } obj = (StatusCode)v; return true; ; }
                    case (int)VariantType.QualifiedName: { if (!this.Decode(out QualifiedName v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.LocalizedText: { if (!this.Decode(out LocalizedText v)) { return false; } obj = v; return true; ; }
                    case (int)VariantType.ExtensionObject: { if (!this.Decode(out ExtensionObject v)) { return false; } obj = v; return true; ; }
                    //case (int)VariantType.DataValue: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    //case (int)VariantType.Variant: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    //case (int)VariantType.DiagnosticInfo: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
                    default:
                        throw new Exception("TODO");
                }
            }

            public MemoryBuffer Duplicate()
            {
                var mb = new MemoryBuffer(Capacity);

                mb.Append(Buffer, Capacity);
                mb.Position = Position;

                return mb;
            }
        }
    }
}
