using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibUA
{
	namespace Core
	{
		public static class ArrayHelper
		{
			public static T[] SubArray<T>(this T[] Data, int Offset, int Length)
			{
				var res = new T[Length];
				Array.Copy(Data, Offset, res, 0, Length);

				return res;
			}

			public static void Memset<T>(this T[] Data, T Value)
			{
				int BlockSize = 32;
				int Index = 0;

				int Length = Math.Min(BlockSize, Data.Length);
				while (Index < Length)
				{
					Data[Index++] = Value;
				}

				Length = Data.Length;
				while (Index < Length)
				{
					Buffer.BlockCopy(Data, 0, Data, Index, Math.Min(BlockSize, Length - Index));
					Index += BlockSize;
					BlockSize *= 2;
				}
			}
		}

		public class MemoryBuffer
		{
			public bool IsReadOnly { get; protected set; }

			int position = 0;
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
				byte b = 0;
				if (!Decode(out b)) { return false; }
				v = b != 0;

				return true;
			}

			public bool Encode(SByte v)
			{
				return Encode((byte)v);
			}

			public bool Decode(out SByte v)
			{
				byte b = 0;
				v = 0;
				if (!Decode(out b)) { return false; }
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
				UInt32 i = 0;
				v = 0;
				if (!Decode(out i)) { return false; }
				v = *(Single*)&i;
				return true;
			}

			public unsafe bool Encode(Double v)
			{
				return Encode(*(UInt64*)&v);
			}

			public unsafe bool Decode(out Double v)
			{
				UInt64 i = 0;
				v = 0;
				if (!Decode(out i)) { return false; }
				v = *(Double*)&i;
				return true;
			}

			public int CodingSize(byte v) { return 1; }
			public int CodingSize(SByte v) { return 1; }
			public int CodingSize(bool v) { return 1; }
			public int CodingSize(Int16 v) { return 2; }
			public int CodingSize(UInt16 v) { return 2; }
			public int CodingSize(Int32 v) { return 4; }
			public int CodingSize(UInt32 v) { return 4; }
			public int CodingSize(Int64 v) { return 8; }
			public int CodingSize(UInt64 v) { return 8; }
			public int CodingSize(Single v) { return 4; }
			public int CodingSize(Double v) { return 8; }

			public int CodingSize(string s) { return CodingSize((int)s.Length) + s.Length; }

			public static int VarLenU32Decode(out UInt32 v, byte[] Src)
			{
				v = 0;

				for (int i = 0, n = 0; i < 5; i++, n += 7)
				{
					int curLen = 1 + i;
					if (Src.Length < curLen)
					{
						return -1;
					}

					v |= (uint)(((byte)(Src[i] >> 1) & 0x7F) << n);
					if ((Src[i] & 1) != 0)
					{
						continue;
					}

					return curLen;
				}

				return 0;
			}

			public static int VarLenU32Encode(UInt32 v, byte[] Dest)
			{
				for (int i = 0, n = 0; i < 5; i++, n += 7)
				{
					if (i == 4 && (v >> n) > 0x7F)
					{
						// Overflow
						break;
					}

					Dest[i] = (byte)(((v >> n) & 0x7F) << 1);
					if ((v >> n) < 0x80)
					{
						return i + 1;
					}

					Dest[i] |= 1;
				}

				// Overflow
				return 0;
			}

			public static int VarLenU32Size(UInt32 v)
			{
				for (int i = 0, n = 0; i < 5; i++, n += 7)
				{
					if (i == 4 && (v >> n) > 0x7F)
					{
						// Overflow
						break;
					}

					if ((v >> n) < 0x80)
					{
						return i + 1;
					}
				}

				// Overflow
				return 0;
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

				int adv = VarLenU32Decode(out v, tmp);
				if (adv > 0)
				{
					Position += adv;
				}

				return adv;
			}

			public int VarLenU32Encode(UInt32 v)
			{
				var buffer = new byte[8];

				int adv = VarLenU32Encode(v, buffer);
				if (adv > 0)
				{
					Append(buffer, adv);
				}

				return adv;
			}

			public static VariantType GetVariantTypeFromType(Type type)
			{
				if (type == typeof(bool)) { return VariantType.Boolean; }
				if (type == typeof(SByte)) { return VariantType.SByte; }
				if (type == typeof(Byte)) { return VariantType.Byte; }
				if (type == typeof(Int16)) { return VariantType.Int16; }
				if (type == typeof(UInt16)) { return VariantType.UInt16; }
				if (type == typeof(Int32)) { return VariantType.Int32; }
				if (type == typeof(UInt32)) { return VariantType.UInt32; }
				if (type == typeof(Int64)) { return VariantType.Int64; }
				if (type == typeof(UInt64)) { return VariantType.UInt64; }
				if (type == typeof(float)) { return VariantType.Float; }
				if (type == typeof(Double)) { return VariantType.Double; }
				if (type == typeof(string)) { return VariantType.String; }
				if (type == typeof(byte[])) { return VariantType.ByteString; }
				if (type == typeof(NodeId)) { return VariantType.NodeId; }
				if (type == typeof(QualifiedName)) { return VariantType.QualifiedName; }
				if (type == typeof(LocalizedText)) { return VariantType.LocalizedText; }
				if (type == typeof(DateTime)) { return VariantType.DateTime; }
				if (type == typeof(StatusCode)) { return VariantType.StatusCode; }

				// TODO: Other types

				return VariantType.Null;
			}


			public static VariantType GetVariantTypeFromInstance(object obj)
			{
				if (obj is bool) { return VariantType.Boolean; }
				if (obj is SByte) { return VariantType.SByte; }
				if (obj is Byte) { return VariantType.Byte; }
				if (obj is Int16) { return VariantType.Int16; }
				if (obj is UInt16) { return VariantType.UInt16; }
				if (obj is Int32) { return VariantType.Int32; }
				if (obj is UInt32) { return VariantType.UInt32; }
				if (obj is Int64) { return VariantType.Int64; }
				if (obj is UInt64) { return VariantType.UInt64; }
				if (obj is float) { return VariantType.Float; }
				if (obj is Double) { return VariantType.Double; }
				if (obj is string) { return VariantType.String; }
				if (obj is byte[]) { return VariantType.ByteString; }
				if (obj is NodeId) { return VariantType.NodeId; }
				if (obj is QualifiedName) { return VariantType.QualifiedName; }
				if (obj is LocalizedText) { return VariantType.LocalizedText; }
				if (obj is DateTime) { return VariantType.DateTime; }
				if (obj is StatusCode) { return VariantType.StatusCode; }

				// TODO: Other types

				return VariantType.Null;
			}

			public static Type GetNetType(VariantType type)
			{
				if (type == VariantType.Boolean) { return typeof(bool); }
				if (type == VariantType.SByte) { return typeof(SByte); }
				if (type == VariantType.Byte) { return typeof(Byte); }
				if (type == VariantType.Int16) { return typeof(Int16); }
				if (type == VariantType.UInt16) { return typeof(UInt16); }
				if (type == VariantType.Int32) { return typeof(Int32); }
				if (type == VariantType.UInt32) { return typeof(UInt32); }
				if (type == VariantType.Int64) { return typeof(Int64); }
				if (type == VariantType.UInt64) { return typeof(UInt64); }
				if (type == VariantType.Float) { return typeof(float); }
				if (type == VariantType.Double) { return typeof(Double); }
				if (type == VariantType.NodeId) { return typeof(NodeId); }
				if (type == VariantType.QualifiedName) { return typeof(QualifiedName); }
				if (type == VariantType.LocalizedText) { return typeof(LocalizedText); }
				if (type == VariantType.String) { return typeof(String); }

				// TODO: Other types

				return null;
			}

			public int VariantCodingSize(object obj)
			{
				int rank = 0;
				VariantType varType = VariantType.Null;

				if (obj is Array && !(obj is byte[]))
				{
					var type = obj.GetType();
					rank = type.GetArrayRank();
					type = type.GetElementType();

					varType = GetVariantTypeFromType(type);
				}
				else
				{
					varType = GetVariantTypeFromInstance(obj);
				}

				int size = 0;

				byte mask = (byte)varType;
				++size;

				if (rank > 1)
				{
					mask |= 0x40;
				}

				if (rank >= 1)
				{
					mask |= 0x80;
					size += CodingSize((int)((Array)obj).Length);

					foreach (var value in obj as Array)
					{
						size += VariantCodingSize(value, mask);
					}

					if (rank > 1)
					{
						size += CodingSize((int)rank) * (1 + rank);
					}
				}
				else
				{
					size += VariantCodingSize(obj, mask);
				}

				return size;
			}

			public bool VariantEncode(object obj)
			{
				int rank = 0;
				VariantType varType = VariantType.Null;

				if (obj is Array && !(obj is byte[]))
				{
					var type = obj.GetType();
					rank = type.GetArrayRank();
					type = type.GetElementType();

					varType = GetVariantTypeFromType(type);
				}
				else
				{
					varType = GetVariantTypeFromInstance(obj);
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

				byte mask;
				if (!Decode(out mask))
				{
					return false;
				}

				if ((mask & 0x80) != 0)
				{
					int arrLen;
					if (!Decode(out arrLen)) { return false; }
					if (arrLen < 0) { return false; }

					int rank = 1;
					if ((mask & 0x40) != 0)
					{
						if (!Decode(out rank)) { return false; }
					}

					Type type = GetNetType((VariantType)(mask & 0x3F));

					var arr = Array.CreateInstance(type, arrLen);
					for (int i = 0; i < arrLen; i++)
					{
						object v;
						if (!VariantDecode(out v, mask))
						{
							return false;
						}

						arr.SetValue(v, i);
					}

					res = arr;

					// Decoding multidimensional arrays is not supported, decode as a flat array.
					if ((mask & 0x40) != 0)
					{
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

			private int VariantCodingSize(object obj, byte mask)
			{
				int size = 0;

				switch (mask & 0x3F)
				{
					case (int)VariantType.Null: break;
					case (int)VariantType.Boolean: size += CodingSize((bool)obj); break;
					case (int)VariantType.SByte: size += CodingSize((SByte)obj); break;
					case (int)VariantType.Byte: size += CodingSize((Byte)obj); break;
					case (int)VariantType.Int16: size += CodingSize((Int16)obj); break;
					case (int)VariantType.UInt16: size += CodingSize((UInt16)obj); break;
					case (int)VariantType.Int32: size += CodingSize((Int32)obj); break;
					case (int)VariantType.UInt32: size += CodingSize((UInt32)obj); break;
					case (int)VariantType.Int64: size += CodingSize((Int64)obj); break;
					case (int)VariantType.UInt64: size += CodingSize((UInt64)obj); break;
					case (int)VariantType.Float: size += CodingSize((Single)obj); break;
					case (int)VariantType.Double: size += CodingSize((Double)obj); break;
					case (int)VariantType.String: size += this.CodingSizeUAString((string)obj); break;
					case (int)VariantType.DateTime: size += CodingSize((Int64)0); break;
					//case (int)VariantType.Guid: size += CodingSize((int)obj); break;
					case (int)VariantType.ByteString: size += this.CodingSizeUAByteString((byte[])obj); break;
					//case (int)VariantType.XmlElement: size += CodingSize((int)obj); break;
					case (int)VariantType.NodeId: size += this.CodingSize((NodeId)obj); break;
					//case (int)VariantType.ExpandedNodeId: size += CodingSize((int)obj); break;
					case (int)VariantType.StatusCode: size += CodingSize((UInt32)obj); break;
					case (int)VariantType.QualifiedName: size += this.CodingSize((QualifiedName)obj); break;
					case (int)VariantType.LocalizedText: size += this.CodingSize((LocalizedText)obj); break;
					case (int)VariantType.ExtensionObject: size += this.CodingSize((ExtensionObject)obj); break;
					//case (int)VariantType.DataValue: size += CodingSize((int)obj); break;
					//case (int)VariantType.Variant: size += CodingSize((int)obj); break;
					//case (int)VariantType.DiagnosticInfo: size += CodingSize((int)obj); break;
					default:
						throw new Exception("TODO");
				}

				return size;
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
					case (int)VariantType.Boolean: { bool v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.SByte: { SByte v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Byte: { Byte v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Int16: { Int16 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.UInt16: { UInt16 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Int32: { Int32 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.UInt32: { UInt32 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Int64: { Int64 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.UInt64: { UInt64 v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Float: { Single v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.Double: { Double v; if (!Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.String: { string v; if (!this.DecodeUAString(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.DateTime: { Int64 v; if (!Decode(out v)) { return false; } obj = DateTime.FromFileTimeUtc(v); return true; ; }
					//case (int)VariantType.Guid: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
					case (int)VariantType.ByteString: { byte[] v; if (!this.DecodeUAByteString(out v)) { return false; } obj = v; return true; ; }
					//case (int)VariantType.XmlElement: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
					case (int)VariantType.NodeId: { NodeId v; if (!this.Decode(out v)) { return false; } obj = v; return true; ; }
					//case (int)VariantType.ExpandedNodeId: { bool v; if (!Decode(out v)) { return false; } obj = v; return true;; }
					case (int)VariantType.StatusCode: { UInt32 v; if (!Decode(out v)) { return false; } obj = (StatusCode)v; return true; ; }
					case (int)VariantType.QualifiedName: { QualifiedName v; if (!this.Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.LocalizedText: { LocalizedText v; if (!this.Decode(out v)) { return false; } obj = v; return true; ; }
					case (int)VariantType.ExtensionObject: { ExtensionObject v; if (!this.Decode(out v)) { return false; } obj = v; return true; ; }
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
