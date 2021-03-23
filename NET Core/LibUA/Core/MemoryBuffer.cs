
// Type: LibUA.Core.MemoryBuffer



using System;

namespace LibUA.Core
{
    public class MemoryBuffer
    {
        private int position = 0;

        public bool IsReadOnly { get; protected set; }

        public int Position
        {
            get
            {
                return this.position;
            }
            set
            {
                this.position = value;
                if (this.position < 0 || this.position > this.Capacity)
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
            return new ArraySegment<byte>(this.Buffer, 0, this.Position);
        }

        public ArraySegment<byte> AsArraySegmentToCapacity()
        {
            return new ArraySegment<byte>(this.Buffer, 0, this.Capacity);
        }

        public ArraySegment<byte> AsArraySegmentPositionToCapacity()
        {
            return new ArraySegment<byte>(this.Buffer, this.Position, this.Capacity - this.Position);
        }

        public bool RestrictCapacity(int newCapacity)
        {
            if (newCapacity <= 0)
            {
                newCapacity = 0;
            }

            if (newCapacity > this.Capacity)
            {
                return false;
            }

            this.Capacity = newCapacity;
            return true;
        }

        public MemoryBuffer()
        {
            this.Position = this.Capacity = this.Allocated = 0;
            this.Buffer = null;
        }

        public MemoryBuffer(byte[] Src)
        {
            this.Position = 0;
            this.IsReadOnly = true;
            if (Src == null)
            {
                this.Capacity = this.Allocated = 0;
            }
            else
            {
                this.Capacity = this.Allocated = Src.Length;
                this.Buffer = Src;
            }
        }

        public MemoryBuffer(byte[] Src, int SrcLength)
        {
            this.Position = 0;
            this.IsReadOnly = true;
            if (Src == null)
            {
                this.Capacity = this.Allocated = 0;
            }
            else
            {
                if (SrcLength > Src.Length)
                {
                    SrcLength = Src.Length;
                }

                this.Capacity = this.Allocated = SrcLength;
                this.Buffer = Src;
            }
        }

        public MemoryBuffer(int Size)
        {
            this.Position = 0;
            this.IsReadOnly = false;
            this.IsFixedCapacity = true;
            this.Buffer = new byte[Size];
            this.Capacity = this.Allocated = Size;
        }

        public bool EnsureAvailable(int Length, bool readOnly)
        {
            if (readOnly)
            {
                return this.Position + Length <= this.Capacity;
            }

            int num = this.Position + Length;
            if (num <= this.Capacity)
            {
                return true;
            }

            if (this.IsFixedCapacity && num > this.Capacity)
            {
                return false;
            }

            if (this.Allocated >= num)
            {
                this.Capacity = num;
                return true;
            }
            try
            {
                int length = Math.Max(num, Math.Max(256, (int)(1.5 * Allocated)));
                byte[] numArray = new byte[length];
                if (this.Buffer != null)
                {
                    Array.Copy(Buffer, numArray, Math.Min(this.Capacity, num));
                }

                this.Buffer = numArray;
                this.Allocated = length;
            }
            catch
            {
                return false;
            }
            this.Capacity = num;
            return true;
        }

        public void Rewind()
        {
            this.Position = 0;
        }

        public bool Append(byte[] Add)
        {
            return this.Append(Add, Add.Length);
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

            if (!this.EnsureAvailable(Size, false))
            {
                return false;
            }

            Array.Copy(Add, 0, Buffer, this.Position, Size);
            this.Position += Size;
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

            if (!this.EnsureAvailable(Size, false))
            {
                return false;
            }

            Array.Copy(Add, Offset, Buffer, this.Position, Size);
            this.Position += Size;
            return true;
        }

        public bool Read(byte[] Dest, int Size)
        {
            if (!this.EnsureAvailable(Size, true))
            {
                return false;
            }

            Array.Copy(Buffer, this.Position, Dest, 0, Size);
            this.Position += Size;
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

            if (!this.EnsureAvailable(Size, false))
            {
                return false;
            }

            byte[] numArray = new byte[this.Position];
            if (this.Position > 0)
            {
                Array.Copy(Buffer, numArray, this.Position);
            }

            Array.Copy(Add, Buffer, Size);
            if (this.Position > 0)
            {
                Array.Copy(numArray, 0, Buffer, Size, this.Position);
            }

            this.Position += Size;
            return true;
        }

        public bool Append(MemoryBuffer Mem)
        {
            return this.Append(Mem.Buffer, Mem.Capacity);
        }

        public bool Encode(byte v)
        {
            if (!this.EnsureAvailable(1, false))
            {
                return false;
            }

            this.Buffer[this.Position++] = v;
            return true;
        }

        public bool Decode(out byte v)
        {
            v = 0;
            if (!this.EnsureAvailable(1, true))
            {
                return false;
            }

            v = this.Buffer[this.Position++];
            return true;
        }

        public bool Encode(bool v)
        {
            return this.Encode(v ? (byte)1 : (byte)0);
        }

        public bool Decode(out bool v)
        {
            v = false;
            if (!this.Decode(out byte v1))
            {
                return false;
            }

            v = v1 > 0;
            return true;
        }

        public bool Encode(sbyte v)
        {
            return this.Encode((byte)v);
        }

        public bool Decode(out sbyte v)
        {
            v = 0;
            if (!this.Decode(out byte v1))
            {
                return false;
            }

            v = (sbyte)v1;
            return true;
        }

        public bool Encode(ushort v)
        {
            if (!this.EnsureAvailable(2, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)(v & (uint)byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Position += 2;
            return true;
        }

        public bool Decode(out ushort v)
        {
            v = 0;
            if (!this.EnsureAvailable(2, true))
            {
                return false;
            }

            v = (ushort)(short)this.Buffer[this.Position];
            v += (ushort)((uint)this.Buffer[this.Position + 1] << 8);
            this.Position += 2;
            return true;
        }

        public bool Encode(short v)
        {
            if (!this.EnsureAvailable(2, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)((uint)v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Position += 2;
            return true;
        }

        public bool Decode(out short v)
        {
            v = 0;
            if (!this.EnsureAvailable(2, true))
            {
                return false;
            }

            v = this.Buffer[this.Position];
            v += (short)(this.Buffer[this.Position + 1] << 8);
            this.Position += 2;
            return true;
        }

        public bool Encode(uint v)
        {
            if (!this.EnsureAvailable(4, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)(v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Buffer[this.Position + 2] = (byte)(v >> 16 & byte.MaxValue);
            this.Buffer[this.Position + 3] = (byte)(v >> 24 & byte.MaxValue);
            this.Position += 4;
            return true;
        }

        public bool Encode(uint v, int pos)
        {
            int position = this.Position;
            this.Position = pos;
            if (!this.EnsureAvailable(4, false))
            {
                this.Position = position;
                return false;
            }
            this.Buffer[this.Position] = (byte)(v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Buffer[this.Position + 2] = (byte)(v >> 16 & byte.MaxValue);
            this.Buffer[this.Position + 3] = (byte)(v >> 24 & byte.MaxValue);
            this.Position = position;
            return true;
        }

        public bool Decode(out uint v)
        {
            v = 0U;
            if (!this.EnsureAvailable(4, true))
            {
                return false;
            }

            v = this.Buffer[this.Position];
            v += (uint)this.Buffer[this.Position + 1] << 8;
            v += (uint)this.Buffer[this.Position + 2] << 16;
            v += (uint)this.Buffer[this.Position + 3] << 24;
            this.Position += 4;
            return true;
        }

        public bool Decode(out uint v, int pos)
        {
            v = 0U;
            if (pos + 4 > this.Buffer.Length)
            {
                return false;
            }

            v = this.Buffer[pos];
            v += (uint)this.Buffer[pos + 1] << 8;
            v += (uint)this.Buffer[pos + 2] << 16;
            v += (uint)this.Buffer[pos + 3] << 24;
            return true;
        }

        public bool Encode(int v)
        {
            if (!this.EnsureAvailable(4, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)(v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Buffer[this.Position + 2] = (byte)(v >> 16 & byte.MaxValue);
            this.Buffer[this.Position + 3] = (byte)(v >> 24 & byte.MaxValue);
            this.Position += 4;
            return true;
        }

        public bool Decode(out int v)
        {
            v = 0;
            if (!this.EnsureAvailable(4, true))
            {
                return false;
            }

            v = this.Buffer[this.Position];
            v += this.Buffer[this.Position + 1] << 8;
            v += this.Buffer[this.Position + 2] << 16;
            v += this.Buffer[this.Position + 3] << 24;
            this.Position += 4;
            return true;
        }

        public bool Encode(ulong v)
        {
            if (!this.EnsureAvailable(8, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)(v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)(v >> 8 & byte.MaxValue);
            this.Buffer[this.Position + 2] = (byte)(v >> 16 & byte.MaxValue);
            this.Buffer[this.Position + 3] = (byte)(v >> 24 & byte.MaxValue);
            this.Buffer[this.Position + 4] = (byte)(v >> 32 & byte.MaxValue);
            this.Buffer[this.Position + 5] = (byte)(v >> 40 & byte.MaxValue);
            this.Buffer[this.Position + 6] = (byte)(v >> 48 & byte.MaxValue);
            this.Buffer[this.Position + 7] = (byte)(v >> 56 & byte.MaxValue);
            this.Position += 8;
            return true;
        }

        public bool Decode(out ulong v)
        {
            v = 0UL;
            if (!this.EnsureAvailable(8, true))
            {
                return false;
            }

            v = this.Buffer[this.Position];
            v += (ulong)this.Buffer[this.Position + 1] << 8;
            v += (ulong)this.Buffer[this.Position + 2] << 16;
            v += (ulong)this.Buffer[this.Position + 3] << 24;
            v += (ulong)this.Buffer[this.Position + 4] << 32;
            v += (ulong)this.Buffer[this.Position + 5] << 40;
            v += (ulong)this.Buffer[this.Position + 6] << 48;
            v += (ulong)this.Buffer[this.Position + 7] << 56;
            this.Position += 8;
            return true;
        }

        public bool Encode(long v)
        {
            if (!this.EnsureAvailable(8, false))
            {
                return false;
            }

            this.Buffer[this.Position] = (byte)((ulong)v & byte.MaxValue);
            this.Buffer[this.Position + 1] = (byte)((ulong)(v >> 8) & byte.MaxValue);
            this.Buffer[this.Position + 2] = (byte)((ulong)(v >> 16) & byte.MaxValue);
            this.Buffer[this.Position + 3] = (byte)((ulong)(v >> 24) & byte.MaxValue);
            this.Buffer[this.Position + 4] = (byte)((ulong)(v >> 32) & byte.MaxValue);
            this.Buffer[this.Position + 5] = (byte)((ulong)(v >> 40) & byte.MaxValue);
            this.Buffer[this.Position + 6] = (byte)((ulong)(v >> 48) & byte.MaxValue);
            this.Buffer[this.Position + 7] = (byte)((ulong)(v >> 56) & byte.MaxValue);
            this.Position += 8;
            return true;
        }

        public bool Decode(out long v)
        {
            v = 0L;
            if (!this.EnsureAvailable(8, true))
            {
                return false;
            }

            v = this.Buffer[this.Position];
            v += (long)this.Buffer[this.Position + 1] << 8;
            v += (long)this.Buffer[this.Position + 2] << 16;
            v += (long)this.Buffer[this.Position + 3] << 24;
            v += (long)this.Buffer[this.Position + 4] << 32;
            v += (long)this.Buffer[this.Position + 5] << 40;
            v += (long)this.Buffer[this.Position + 6] << 48;
            v += (long)this.Buffer[this.Position + 7] << 56;
            this.Position += 8;
            return true;
        }

        public unsafe bool Encode(float v)
        {
            return this.Encode(*(uint*)&v);
        }

        public unsafe bool Decode(out float v)
        {
            v = 0.0f;
            if (!this.Decode(out uint v1))
            {
                return false;
            }

            v = *(float*)&v1;
            return true;
        }

        public unsafe bool Encode(double v)
        {
            return this.Encode((ulong)*(long*)&v);
        }

        public unsafe bool Decode(out double v)
        {
            v = 0.0;
            if (!this.Decode(out ulong v1))
            {
                return false;
            }

            v = *(double*)&v1;
            return true;
        }

        public int CodingSize(byte v)
        {
            return 1;
        }

        public int CodingSize(sbyte v)
        {
            return 1;
        }

        public int CodingSize(bool v)
        {
            return 1;
        }

        public int CodingSize(short v)
        {
            return 2;
        }

        public int CodingSize(ushort v)
        {
            return 2;
        }

        public int CodingSize(int v)
        {
            return 4;
        }

        public int CodingSize(uint v)
        {
            return 4;
        }

        public int CodingSize(long v)
        {
            return 8;
        }

        public int CodingSize(ulong v)
        {
            return 8;
        }

        public int CodingSize(float v)
        {
            return 4;
        }

        public int CodingSize(double v)
        {
            return 8;
        }

        public int CodingSize(string s)
        {
            return this.CodingSize(s.Length) + s.Length;
        }

        public static int VarLenU32Decode(out uint v, byte[] Src)
        {
            v = 0U;
            int index = 0;
            int num1 = 0;
            while (index < 5)
            {
                int num2 = 1 + index;
                if (Src.Length < num2)
                {
                    return -1;
                }

                v |= (uint)(((byte)((uint)Src[index] >> 1) & sbyte.MaxValue) << num1);
                if ((Src[index] & 1U) <= 0U)
                {
                    return num2;
                }

                ++index;
                num1 += 7;
            }
            return 0;
        }

        public static int VarLenU32Encode(uint v, byte[] Dest)
        {
            int index1 = 0;
            for (int index2 = 0; index1 < 5 && (index1 != 4 || v >> index2 <= (uint)sbyte.MaxValue); index2 += 7)
            {
                Dest[index1] = (byte)(((int)(v >> index2) & sbyte.MaxValue) << 1);
                if (v >> index2 < 128U)
                {
                    return index1 + 1;
                }

                Dest[index1] |= 1;
                ++index1;
            }
            return 0;
        }

        public static int VarLenU32Size(uint v)
        {
            int num = 0;
            for (int index = 0; num < 5 && (num != 4 || v >> index <= (uint)sbyte.MaxValue); index += 7)
            {
                if (v >> index < 128U)
                {
                    return num + 1;
                }

                ++num;
            }
            return 0;
        }

        public int VarLenU32Decode(out uint v)
        {
            int num1 = this.Capacity - this.Position;
            int length = num1 > 8 ? 8 : num1;
            byte[] Src = new byte[length];
            if (length > 0)
            {
                Array.Copy(Buffer, this.Position, Src, 0, length);
            }

            int num2 = MemoryBuffer.VarLenU32Decode(out v, Src);
            if (num2 > 0)
            {
                this.Position += num2;
            }

            return num2;
        }

        public int VarLenU32Encode(uint v)
        {
            byte[] numArray = new byte[8];
            int Size = MemoryBuffer.VarLenU32Encode(v, numArray);
            if (Size > 0)
            {
                this.Append(numArray, Size);
            }

            return Size;
        }

        public static VariantType GetVariantTypeFromType(Type type)
        {
            if (type == typeof(bool))
            {
                return VariantType.Boolean;
            }

            if (type == typeof(sbyte))
            {
                return VariantType.SByte;
            }

            if (type == typeof(byte))
            {
                return VariantType.Byte;
            }

            if (type == typeof(short))
            {
                return VariantType.Int16;
            }

            if (type == typeof(ushort))
            {
                return VariantType.UInt16;
            }

            if (type == typeof(int))
            {
                return VariantType.Int32;
            }

            if (type == typeof(uint))
            {
                return VariantType.UInt32;
            }

            if (type == typeof(long))
            {
                return VariantType.Int64;
            }

            if (type == typeof(ulong))
            {
                return VariantType.UInt64;
            }

            if (type == typeof(float))
            {
                return VariantType.Float;
            }

            if (type == typeof(double))
            {
                return VariantType.Double;
            }

            if (type == typeof(string))
            {
                return VariantType.String;
            }

            if (type == typeof(byte[]))
            {
                return VariantType.ByteString;
            }

            if (type == typeof(NodeId))
            {
                return VariantType.NodeId;
            }

            if (type == typeof(QualifiedName))
            {
                return VariantType.QualifiedName;
            }

            if (type == typeof(LocalizedText))
            {
                return VariantType.LocalizedText;
            }

            if (type == typeof(DateTime))
            {
                return VariantType.DateTime;
            }

            return type == typeof(StatusCode) ? VariantType.StatusCode : VariantType.Null;
        }

        public static VariantType GetVariantTypeFromInstance(object obj)
        {
            switch (obj)
            {
                case bool _:
                    return VariantType.Boolean;
                case sbyte _:
                    return VariantType.SByte;
                case byte _:
                    return VariantType.Byte;
                case short _:
                    return VariantType.Int16;
                case ushort _:
                    return VariantType.UInt16;
                case int _:
                    return VariantType.Int32;
                case uint _:
                    return VariantType.UInt32;
                case long _:
                    return VariantType.Int64;
                case ulong _:
                    return VariantType.UInt64;
                case float _:
                    return VariantType.Float;
                case double _:
                    return VariantType.Double;
                case string _:
                    return VariantType.String;
                case byte[] _:
                    return VariantType.ByteString;
                case NodeId _:
                    return VariantType.NodeId;
                case QualifiedName _:
                    return VariantType.QualifiedName;
                case LocalizedText _:
                    return VariantType.LocalizedText;
                case DateTime _:
                    return VariantType.DateTime;
                case StatusCode _:
                    return VariantType.StatusCode;
                default:
                    return VariantType.Null;
            }
        }

        public static Type GetNetType(VariantType type)
        {
            switch (type)
            {
                case VariantType.Boolean:
                    return typeof(bool);
                case VariantType.SByte:
                    return typeof(sbyte);
                case VariantType.Byte:
                    return typeof(byte);
                case VariantType.Int16:
                    return typeof(short);
                case VariantType.UInt16:
                    return typeof(ushort);
                case VariantType.Int32:
                    return typeof(int);
                case VariantType.UInt32:
                    return typeof(uint);
                case VariantType.Int64:
                    return typeof(long);
                case VariantType.UInt64:
                    return typeof(ulong);
                case VariantType.Float:
                    return typeof(float);
                case VariantType.Double:
                    return typeof(double);
                case VariantType.String:
                    return typeof(string);
                case VariantType.NodeId:
                    return typeof(NodeId);
                case VariantType.QualifiedName:
                    return typeof(QualifiedName);
                case VariantType.LocalizedText:
                    return typeof(LocalizedText);
                default:
                    return null;
            }
        }

        public int VariantCodingSize(object obj)
        {
            int num1 = 0;
            bool flag = false;
            VariantType variantType;
            if (obj is Array && !(obj is byte[]))
            {
                Type type = obj.GetType();
                flag = true;
                num1 = type.GetArrayRank();
                Type elementType = type.GetElementType();
                if (num1 > 1)
                {
                    throw new Exception("TODO");
                }

                variantType = MemoryBuffer.GetVariantTypeFromType(elementType);
            }
            else
            {
                variantType = MemoryBuffer.GetVariantTypeFromInstance(obj);
            }

            int num2 = 0;
            byte mask1 = (byte)variantType;
            int num3 = num2 + 1;
            if (num1 > 1)
            {
                mask1 |= 64;
            }

            int num4;
            if (flag)
            {
                byte mask2 = (byte)(mask1 | 128U);
                num4 = num3 + this.CodingSize(((Array)obj).Length);
                Array array = (Array)obj;
                for (int index = 0; index < array.Length; ++index)
                {
                    num4 += this.VariantCodingSize(array.GetValue(index), mask2);
                }
            }
            else
            {
                num4 = num3 + this.VariantCodingSize(obj, mask1);
            }

            return num4;
        }

        public bool VariantEncode(object obj)
        {
            int num1 = 0;
            bool flag = false;
            VariantType variantType;
            if (obj is Array && !(obj is byte[]))
            {
                Type type = obj.GetType();
                flag = true;
                num1 = type.GetArrayRank();
                Type elementType = type.GetElementType();
                if (num1 > 1)
                {
                    throw new Exception("TODO");
                }

                variantType = MemoryBuffer.GetVariantTypeFromType(elementType);
            }
            else
            {
                variantType = MemoryBuffer.GetVariantTypeFromInstance(obj);
            }

            byte num2 = (byte)variantType;
            if (num1 > 1)
            {
                num2 |= 64;
            }

            if (flag)
            {
                byte num3 = (byte)(num2 | 128U);
                if (!this.Encode(num3) || !this.Encode(((Array)obj).Length))
                {
                    return false;
                }

                Array array = (Array)obj;
                for (int index = 0; index < array.Length; ++index)
                {
                    if (!this.VariantEncode(array.GetValue(index), num3))
                    {
                        return false;
                    }
                }
            }
            else if (!this.Encode(num2) || !this.VariantEncode(obj, num2))
            {
                return false;
            }

            return true;
        }

        private int VariantCodingSize(object obj, byte mask)
        {
            int num = 0;
            switch (mask & 63)
            {
                case 0:
                    return num;
                case 1:
                    num += this.CodingSize((bool)obj);
                    goto case 0;
                case 2:
                    num += this.CodingSize((sbyte)obj);
                    goto case 0;
                case 3:
                    num += this.CodingSize((byte)obj);
                    goto case 0;
                case 4:
                    num += this.CodingSize((short)obj);
                    goto case 0;
                case 5:
                    num += this.CodingSize((ushort)obj);
                    goto case 0;
                case 6:
                    num += this.CodingSize((int)obj);
                    goto case 0;
                case 7:
                    num += this.CodingSize((uint)obj);
                    goto case 0;
                case 8:
                    num += this.CodingSize((long)obj);
                    goto case 0;
                case 9:
                    num += this.CodingSize((ulong)obj);
                    goto case 0;
                case 10:
                    num += this.CodingSize((float)obj);
                    goto case 0;
                case 11:
                    num += this.CodingSize((double)obj);
                    goto case 0;
                case 12:
                    num += this.CodingSizeUAString((string)obj);
                    goto case 0;
                case 13:
                    num += this.CodingSize(0L);
                    goto case 0;
                case 15:
                    num += this.CodingSizeUAByteString((byte[])obj);
                    goto case 0;
                case 17:
                    num += this.CodingSize((NodeId)obj);
                    goto case 0;
                case 19:
                    num += this.CodingSize((uint)obj);
                    goto case 0;
                case 20:
                    num += this.CodingSize((QualifiedName)obj);
                    goto case 0;
                case 21:
                    num += this.CodingSize((LocalizedText)obj);
                    goto case 0;
                case 22:
                    num += this.CodingSize((ExtensionObject)obj);
                    goto case 0;
                default:
                    throw new Exception("TODO");
            }
        }

        public bool VariantDecode(out object res)
        {
            res = null;
            if (!this.Decode(out byte v1))
            {
                return false;
            }

            if ((v1 & 128U) > 0U)
            {
                if (!this.Decode(out int v2) || v2 < 0)
                {
                    return false;
                }

                Array instance = Array.CreateInstance(MemoryBuffer.GetNetType((VariantType)(v1 & 63)), v2);
                for (int index = 0; index < v2; ++index)
                {
                    if (!this.VariantDecode(out object obj, v1))
                    {
                        return false;
                    }

                    instance.SetValue(obj, index);
                }
                res = instance;
            }
            else if (!this.VariantDecode(out res, v1))
            {
                return false;
            }

            return true;
        }

        public bool VariantEncode(object obj, byte mask)
        {
            switch (mask & 63)
            {
                case 0:
                    return true;
                case 1:
                    return this.Encode((bool)obj);
                case 2:
                    return this.Encode((sbyte)obj);
                case 3:
                    return this.Encode((byte)obj);
                case 4:
                    return this.Encode((short)obj);
                case 5:
                    return this.Encode((ushort)obj);
                case 6:
                    return this.Encode((int)obj);
                case 7:
                    return this.Encode((uint)obj);
                case 8:
                    return this.Encode((long)obj);
                case 9:
                    return this.Encode((ulong)obj);
                case 10:
                    return this.Encode((float)obj);
                case 11:
                    return this.Encode((double)obj);
                case 12:
                    return this.EncodeUAString((string)obj);
                case 13:
                    return this.Encode(((DateTime)obj).ToFileTimeUtc());
                case 15:
                    return this.EncodeUAByteString((byte[])obj);
                case 17:
                    return this.Encode((NodeId)obj);
                case 19:
                    return this.Encode((uint)obj);
                case 20:
                    return this.Encode((QualifiedName)obj);
                case 21:
                    return this.Encode((LocalizedText)obj);
                case 22:
                    return this.Encode((ExtensionObject)obj);
                default:
                    throw new Exception("TODO");
            }
        }

        public bool VariantDecode(out object obj, byte mask)
        {
            obj = null;
            switch (mask & 63)
            {
                case 0:
                case 1:
                    bool v1;
                    if (!this.Decode(out v1))
                    {
                        return false;
                    }

                    obj = v1;
                    return true;
                case 2:
                    sbyte v2;
                    if (!this.Decode(out v2))
                    {
                        return false;
                    }

                    obj = v2;
                    return true;
                case 3:
                    byte v3;
                    if (!this.Decode(out v3))
                    {
                        return false;
                    }

                    obj = v3;
                    return true;
                case 4:
                    short v4;
                    if (!this.Decode(out v4))
                    {
                        return false;
                    }

                    obj = v4;
                    return true;
                case 5:
                    ushort v5;
                    if (!this.Decode(out v5))
                    {
                        return false;
                    }

                    obj = v5;
                    return true;
                case 6:
                    int v6;
                    if (!this.Decode(out v6))
                    {
                        return false;
                    }

                    obj = v6;
                    return true;
                case 7:
                    uint v7;
                    if (!this.Decode(out v7))
                    {
                        return false;
                    }

                    obj = v7;
                    return true;
                case 8:
                    long v8;
                    if (!this.Decode(out v8))
                    {
                        return false;
                    }

                    obj = v8;
                    return true;
                case 9:
                    ulong v9;
                    if (!this.Decode(out v9))
                    {
                        return false;
                    }

                    obj = v9;
                    return true;
                case 10:
                    float v10;
                    if (!this.Decode(out v10))
                    {
                        return false;
                    }

                    obj = v10;
                    return true;
                case 11:
                    double v11;
                    if (!this.Decode(out v11))
                    {
                        return false;
                    }

                    obj = v11;
                    return true;
                case 12:
                    string str1;
                    if (!this.DecodeUAString(out str1))
                    {
                        return false;
                    }

                    obj = str1;
                    return true;
                case 13:
                    long v12;
                    if (!this.Decode(out v12))
                    {
                        return false;
                    }

                    obj = DateTime.FromFileTimeUtc(v12);
                    return true;
                case 15:
                    byte[] str2;
                    if (!this.DecodeUAByteString(out str2))
                    {
                        return false;
                    }

                    obj = str2;
                    return true;
                case 17:
                    NodeId id;
                    if (!this.Decode(out id))
                    {
                        return false;
                    }

                    obj = id;
                    return true;
                case 19:
                    uint v13;
                    if (!this.Decode(out v13))
                    {
                        return false;
                    }

                    obj = (StatusCode)v13;
                    return true;
                case 20:
                    QualifiedName qn;
                    if (!this.Decode(out qn))
                    {
                        return false;
                    }

                    obj = qn;
                    return true;
                case 21:
                    LocalizedText ad;
                    if (!this.Decode(out ad))
                    {
                        return false;
                    }

                    obj = ad;
                    return true;
                case 22:
                    ExtensionObject extensionObject;
                    if (!this.Decode(out extensionObject))
                    {
                        return false;
                    }

                    obj = extensionObject;
                    return true;
                default:
                    throw new Exception("TODO");
            }
        }

        public MemoryBuffer Duplicate()
        {
            MemoryBuffer memoryBuffer = new MemoryBuffer(this.Capacity);
            memoryBuffer.Append(this.Buffer, this.Capacity);
            memoryBuffer.Position = this.Position;
            return memoryBuffer;
        }
    }
}
