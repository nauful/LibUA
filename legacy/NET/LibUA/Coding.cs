using System;
using System.Text;

namespace LibUA
{
    namespace Core
    {
        public class Coding
        {
            public static int CodingSize(byte v) { return 1; }
            public static int CodingSize(SByte v) { return 1; }
            public static int CodingSize(bool v) { return 1; }
            public static int CodingSize(Int16 v) { return 2; }
            public static int CodingSize(UInt16 v) { return 2; }
            public static int CodingSize(Int32 v) { return 4; }
            public static int CodingSize(UInt32 v) { return 4; }
            public static int CodingSize(Int64 v) { return 8; }
            public static int CodingSize(UInt64 v) { return 8; }
            public static int CodingSize(Single v) { return 4; }
            public static int CodingSize(Double v) { return 8; }
            public static int CodingSize(string s) { return CodingSize((int)s.Length) + s.Length; }
            public static int CodingSize(NodeId id)
            {
                switch (id.IdType)
                {
                    case NodeIdNetType.Numeric:
                        {
                            if (id.NamespaceIndex == 0 && id.NumericIdentifier <= 0xFF)
                            {
                                return 2;
                            }
                            else if (id.NamespaceIndex <= 0xFF && id.NumericIdentifier <= 0xFFFF)
                            {
                                return 4;
                            }
                            else
                            {
                                return 7;
                            }
                        }

                    case NodeIdNetType.String:
                        {
                            return 3 + Coding.CodingSizeUAString(id.StringIdentifier);
                        }

                    default:
                        // TODO: Handle
                        throw new Exception();
                }
            }
            public static int CodingSize(QualifiedName qn)
            {
                return Coding.CodingSize(qn.NamespaceIndex) + Coding.CodingSizeUAString(qn.Name);
            }
            public static int CodingSize(LocalizedText ad)
            {
                int size = Coding.CodingSize((byte)0);
                if (!string.IsNullOrEmpty(ad.Locale)) { size += Coding.CodingSizeUAString(ad.Locale); }
                if (!string.IsNullOrEmpty(ad.Text)) { size += Coding.CodingSizeUAString(ad.Text); }

                return size;
            }
            public static int CodingSize(ExtensionObject obj)
            {
                int size = 0;

                if (obj == null)
                {
                    size = Coding.CodingSize(NodeId.Zero);
                    size += Coding.CodingSize((byte)ExtensionObjectBodyType.None);
                    return size;
                }

                size += Coding.CodingSize(obj.TypeId);
                size += Coding.CodingSize((byte)ExtensionObjectBodyType.None);

                if (obj.Body == null)
                {
                    return size;
                }

                size += Coding.CodingSizeUAByteString(obj.Body);

                return size;
            }
            public static int CodingSizeUAByteString(byte[] str)
            {
                if (str == null) { return Coding.CodingSize((UInt32)0); }

                return Coding.CodingSize((UInt32)0) + str.Length;
            }
            public static int CodingSizeUAGuidByteString(byte[] str)
            {
                if (str == null) { return 0; }

                return str.Length;
            }
            public static int CodingSizeUAString(string str)
            {
                if (str == null) { return Coding.CodingSize((UInt32)0); }

                return Coding.CodingSize((UInt32)0) + Encoding.UTF8.GetBytes(str).Length;
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
                if (type == VariantType.ExtensionObject) { return typeof(ExtensionObject); }

                // TODO: Other types

                return null;
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
                if (obj is ExtensionObject) { return VariantType.ExtensionObject; }

                // TODO: Other types

                return VariantType.Null;
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
                if (type == typeof(ExtensionObject)) { return VariantType.ExtensionObject; }

                // TODO: Other types

                return VariantType.Null;
            }

            public static int VariantCodingSize(object obj)
            {
                int rank = 0;
                VariantType varType;
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

            private static int VariantCodingSize(object obj, byte mask)
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
                    case (int)VariantType.String: size += CodingSizeUAString((string)obj); break;
                    case (int)VariantType.DateTime: size += CodingSize((Int64)0); break;
                    //case (int)VariantType.Guid: size += CodingSize((int)obj); break;
                    case (int)VariantType.ByteString: size += CodingSizeUAByteString((byte[])obj); break;
                    //case (int)VariantType.XmlElement: size += CodingSize((int)obj); break;
                    case (int)VariantType.NodeId: size += CodingSize((NodeId)obj); break;
                    //case (int)VariantType.ExpandedNodeId: size += CodingSize((int)obj); break;
                    case (int)VariantType.StatusCode: size += CodingSize((UInt32)obj); break;
                    case (int)VariantType.QualifiedName: size += CodingSize((QualifiedName)obj); break;
                    case (int)VariantType.LocalizedText: size += CodingSize((LocalizedText)obj); break;
                    case (int)VariantType.ExtensionObject: size += CodingSize((ExtensionObject)obj); break;
                    //case (int)VariantType.DataValue: size += CodingSize((int)obj); break;
                    //case (int)VariantType.Variant: size += CodingSize((int)obj); break;
                    //case (int)VariantType.DiagnosticInfo: size += CodingSize((int)obj); break;
                    default:
                        throw new Exception("TODO");
                }

                return size;
            }
        }
    }
}


