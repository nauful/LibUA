
// Type: LibUA.MemoryBufferExtensions



using LibUA.Core;
using System;
using System.Collections.Generic;
using System.Text;

namespace LibUA
{
    public static class MemoryBufferExtensions
    {
        private static byte DoubleToByte(double v)
        {
            int num = (int)(v / 1.0);
            if (num <= 0)
            {
                return 0;
            }

            return num >= byte.MaxValue ? byte.MaxValue : (byte)num;
        }

        private static double ByteToDouble(byte b)
        {
            return b / (double)byte.MaxValue;
        }

        public static bool Encode(this MemoryBuffer mem, AggregateConfiguration ac)
        {
            return mem.Encode(ac.UseServerCapabilitiesDefaults) && mem.Encode(ac.TreatUncertainAsBad) && (mem.Encode(MemoryBufferExtensions.DoubleToByte(ac.PercentDataBad)) && mem.Encode(MemoryBufferExtensions.DoubleToByte(ac.PercentDataGood))) && mem.Encode(ac.UseSlopedExtrapolation);
        }

        public static bool Decode(this MemoryBuffer mem, out AggregateConfiguration ac)
        {
            ac = null;
            if (!mem.Decode(out bool v1) || !mem.Decode(out bool v2) || (!mem.Decode(out byte v3) || !mem.Decode(out byte v4)))
            {
                return false;
            }

            if (!mem.Decode(out bool v5))
            {
                return false;
            }

            try
            {
                ac = new AggregateConfiguration(v1, v2, MemoryBufferExtensions.ByteToDouble(v3), MemoryBufferExtensions.ByteToDouble(v4), v5);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, WriteValue wv)
        {
            return mem.Encode(wv.NodeId) && mem.Encode((uint)wv.AttributeId) && (mem.EncodeUAString(wv.IndexRange) && mem.Encode(wv.Value));
        }

        public static bool Decode(this MemoryBuffer mem, out WriteValue wv)
        {
            wv = null;
            if (!mem.Decode(out NodeId id) || !mem.Decode(out uint v) || !mem.DecodeUAString(out string str))
            {
                return false;
            }

            if (!mem.Decode(out DataValue dv))
            {
                return false;
            }

            try
            {
                wv = new WriteValue(id, (NodeAttribute)v, str, dv);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ObjectAttributes item)
        {
            return mem.Encode((uint)item.SpecifiedAttributes) && mem.Encode(item.DisplayName) && (mem.Encode(item.Description) && mem.Encode(item.WriteMask)) && (mem.Encode(item.UserWriteMask) && mem.Encode(item.EventNotifier));
        }

        public static bool Decode(this MemoryBuffer mem, out ObjectAttributes item)
        {
            item = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out LocalizedText ad1) || (!mem.Decode(out LocalizedText ad2) || !mem.Decode(out uint v2)) || !mem.Decode(out uint v3))
            {
                return false;
            }

            if (!mem.Decode(out byte v4))
            {
                return false;
            }

            try
            {
                item = new ObjectAttributes()
                {
                    SpecifiedAttributes = (NodeAttributesMask)v1,
                    DisplayName = ad1,
                    Description = ad2,
                    WriteMask = v2,
                    UserWriteMask = v3,
                    EventNotifier = v4
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ObjectTypeAttributes item)
        {
            return mem.Encode((uint)item.SpecifiedAttributes) && mem.Encode(item.DisplayName) && (mem.Encode(item.Description) && mem.Encode(item.WriteMask)) && (mem.Encode(item.UserWriteMask) && mem.Encode(item.IsAbstract));
        }

        public static bool Decode(this MemoryBuffer mem, out ObjectTypeAttributes item)
        {
            item = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out LocalizedText ad1) || (!mem.Decode(out LocalizedText ad2) || !mem.Decode(out uint v2)) || !mem.Decode(out uint v3))
            {
                return false;
            }

            if (!mem.Decode(out bool v4))
            {
                return false;
            }

            try
            {
                item = new ObjectTypeAttributes()
                {
                    SpecifiedAttributes = (NodeAttributesMask)v1,
                    DisplayName = ad1,
                    Description = ad2,
                    WriteMask = v2,
                    UserWriteMask = v3,
                    IsAbstract = v4
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, VariableAttributes item)
        {
            if (!mem.Encode((uint)item.SpecifiedAttributes) || !mem.Encode(item.DisplayName) || (!mem.Encode(item.Description) || !mem.Encode(item.WriteMask)) || (!mem.Encode(item.UserWriteMask) || !mem.VariantEncode(item.Value) || (!mem.Encode(item.DataType) || !mem.Encode(item.ValueRank))) || !mem.Encode(item.ArrayDimensions.Length))
            {
                return false;
            }

            for (int index = 0; index < item.ArrayDimensions.Length; ++index)
            {
                if (!mem.Encode(item.ArrayDimensions[index]))
                {
                    return false;
                }
            }
            return mem.Encode(item.AccessLevel) && mem.Encode(item.UserAccessLevel) && (mem.Encode(item.MinimumSamplingInterval) && mem.Encode(item.Historizing));
        }

        public static bool Decode(this MemoryBuffer mem, out VariableAttributes item)
        {
            item = null;
            LocalizedText ad1 = new LocalizedText("");
            LocalizedText ad2 = new LocalizedText("");
            NodeId id = new NodeId(0U);
            if (!mem.Decode(out uint v8) || !mem.Decode(out ad1) || (!mem.Decode(out ad2) || !mem.Decode(out uint v1)) || (!mem.Decode(out uint v2) || !mem.VariantDecode(out object res) || (!mem.Decode(out id) || !mem.Decode(out int v3))) || !mem.Decode(out uint v9))
            {
                return false;
            }

            uint[] numArray;
            if (v9 == uint.MaxValue)
            {
                numArray = null;
            }
            else
            {
                numArray = new uint[(int)v9];
                for (int index = 0; index < v9; ++index)
                {
                    if (!mem.Decode(out numArray[index]))
                    {
                        return false;
                    }
                }
            }
            if (!mem.Decode(out byte v4) || !mem.Decode(out byte v5) || !mem.Decode(out double v6))
            {
                return false;
            }

            if (!mem.Decode(out bool v7))
            {
                return false;
            }

            try
            {
                item = new VariableAttributes()
                {
                    SpecifiedAttributes = (NodeAttributesMask)v8,
                    DisplayName = ad1,
                    Description = ad2,
                    WriteMask = v1,
                    UserWriteMask = v2,
                    Value = res,
                    DataType = id,
                    ValueRank = v3,
                    ArrayDimensions = numArray,
                    AccessLevel = v4,
                    UserAccessLevel = v5,
                    MinimumSamplingInterval = v6,
                    Historizing = v7
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, VariableTypeAttributes item)
        {
            if (!mem.Encode((uint)item.SpecifiedAttributes) || !mem.Encode(item.DisplayName) || (!mem.Encode(item.Description) || !mem.Encode(item.WriteMask)) || (!mem.Encode(item.UserWriteMask) || !mem.VariantEncode(item.Value) || (!mem.Encode(item.DataType) || !mem.Encode(item.ValueRank))) || !mem.Encode(item.ArrayDimensions.Length))
            {
                return false;
            }

            for (int index = 0; index < item.ArrayDimensions.Length; ++index)
            {
                if (!mem.Encode(item.ArrayDimensions[index]))
                {
                    return false;
                }
            }
            return mem.Encode(item.IsAbstract);
        }

        public static bool Decode(this MemoryBuffer mem, out VariableTypeAttributes item)
        {
            item = null;
            LocalizedText ad1 = new LocalizedText("");
            LocalizedText ad2 = new LocalizedText("");
            NodeId id = new NodeId(0U);
            if (!mem.Decode(out uint v5) || !mem.Decode(out ad1) || (!mem.Decode(out ad2) || !mem.Decode(out uint v1)) || (!mem.Decode(out uint v2) || !mem.VariantDecode(out object res) || (!mem.Decode(out id) || !mem.Decode(out int v3))) || !mem.Decode(out uint v6))
            {
                return false;
            }

            uint[] numArray;
            if (v6 == uint.MaxValue)
            {
                numArray = null;
            }
            else
            {
                numArray = new uint[(int)v6];
                for (int index = 0; index < v6; ++index)
                {
                    if (!mem.Decode(out numArray[index]))
                    {
                        return false;
                    }
                }
            }
            if (!mem.Decode(out bool v4))
            {
                return false;
            }

            try
            {
                item = new VariableTypeAttributes()
                {
                    SpecifiedAttributes = (NodeAttributesMask)v5,
                    DisplayName = ad1,
                    Description = ad2,
                    WriteMask = v1,
                    UserWriteMask = v2,
                    Value = res,
                    DataType = id,
                    ValueRank = v3,
                    ArrayDimensions = numArray,
                    IsAbstract = v4
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, AddNodesItem item)
        {
            return mem.Encode(item.ParentNodeId) && mem.Encode(item.ReferenceTypeId) && (mem.Encode(item.RequestedNewNodeId) && mem.Encode(item.BrowseName)) && (mem.Encode((uint)item.NodeClass) && mem.Encode(item.NodeAttributes) && mem.Encode(item.TypeDefinition));
        }

        public static bool Decode(this MemoryBuffer mem, out AddNodesItem item)
        {
            item = null;
            if (!mem.Decode(out NodeId id1) || !mem.Decode(out NodeId id2) || (!mem.Decode(out NodeId id3) || !mem.Decode(out QualifiedName qn)) || (!mem.Decode(out uint v) || !mem.Decode(out ExtensionObject extensionObject)))
            {
                return false;
            }

            if (!mem.Decode(out NodeId id4))
            {
                return false;
            }

            try
            {
                item = new AddNodesItem()
                {
                    ParentNodeId = id1,
                    ReferenceTypeId = id2,
                    RequestedNewNodeId = id3,
                    BrowseName = qn,
                    NodeClass = (NodeClass)v,
                    NodeAttributes = extensionObject,
                    TypeDefinition = id4
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, AddNodesResult res)
        {
            return mem.Encode((uint)res.StatusCode) && mem.Encode(res.AddedNodeId);
        }

        public static bool Decode(this MemoryBuffer mem, out AddNodesResult res)
        {
            res = null;
            if (!mem.Decode(out uint v))
            {
                return false;
            }

            if (!mem.Decode(out NodeId id))
            {
                return false;
            }

            try
            {
                res = new AddNodesResult((StatusCode)v, id);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, DeleteNodesItem item)
        {
            return mem.Encode(item.NodeId) && mem.Encode(item.DeleteTargetReferences);
        }

        public static bool Decode(this MemoryBuffer mem, out DeleteNodesItem item)
        {
            item = null;
            if (!mem.Decode(out NodeId id))
            {
                return false;
            }

            if (!mem.Decode(out bool v))
            {
                return false;
            }

            try
            {
                item = new DeleteNodesItem(id, v);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, AddReferencesItem item)
        {
            return mem.Encode(item.SourceNodeId) && mem.Encode(item.ReferenceTypeId) && (mem.Encode(item.IsForward) && mem.EncodeUAString(item.TargetServerUri)) && (mem.Encode(item.TargetNodeId) && mem.Encode((uint)item.TargetNodeClass));
        }

        public static bool Decode(this MemoryBuffer mem, out AddReferencesItem item)
        {
            item = null;
            if (!mem.Decode(out NodeId id1) || !mem.Decode(out NodeId id2) || (!mem.Decode(out bool v1) || !mem.DecodeUAString(out string str)) || !mem.Decode(out NodeId id3))
            {
                return false;
            }

            if (!mem.Decode(out uint v2))
            {
                return false;
            }

            try
            {
                item = new AddReferencesItem()
                {
                    SourceNodeId = id1,
                    ReferenceTypeId = id2,
                    IsForward = v1,
                    TargetServerUri = str,
                    TargetNodeId = id3,
                    TargetNodeClass = (NodeClass)v2
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, DeleteReferencesItem item)
        {
            return mem.Encode(item.SourceNodeId) && mem.Encode(item.ReferenceTypeId) && (mem.Encode(item.IsForward) && mem.Encode(item.TargetNodeId)) && mem.Encode(item.DeleteBidirectional);
        }

        public static bool Decode(this MemoryBuffer mem, out DeleteReferencesItem item)
        {
            item = null;
            if (!mem.Decode(out NodeId id1) || !mem.Decode(out NodeId id2) || (!mem.Decode(out bool v1) || !mem.Decode(out NodeId id3)))
            {
                return false;
            }

            if (!mem.Decode(out bool v2))
            {
                return false;
            }

            try
            {
                item = new DeleteReferencesItem()
                {
                    SourceNodeId = id1,
                    ReferenceTypeId = id2,
                    IsForward = v1,
                    TargetNodeId = id3,
                    DeleteBidirectional = v2
                };
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemModifyRequest rq)
        {
            return mem.Encode(rq.MonitoredItemId) && mem.Encode(rq.Parameters);
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemModifyRequest rq)
        {
            rq = null;
            if (!mem.Decode(out uint v))
            {
                return false;
            }

            if (!mem.Decode(out MonitoringParameters para))
            {
                return false;
            }

            try
            {
                rq = new MonitoredItemModifyRequest(v, para);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out BrowsePathResult bp)
        {
            bp = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out uint v2))
            {
                return false;
            }

            BrowsePathTarget[] Targets = new BrowsePathTarget[(int)v2];
            for (uint index = 0; index < v2; ++index)
            {
                if (!mem.Decode(out Targets[(int)index].Target) || !mem.Decode(out Targets[(int)index].RemainingPathIndex))
                {
                    return false;
                }
            }
            try
            {
                bp = new BrowsePathResult((StatusCode)v1, Targets);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowsePathResult bp)
        {
            if (!mem.Encode((uint)bp.StatusCode))
            {
                return false;
            }

            if (bp.Targets == null)
            {
                return mem.Encode(uint.MaxValue);
            }

            if (!mem.Encode((uint)bp.Targets.Length))
            {
                return false;
            }

            for (int index = 0; index < bp.Targets.Length; ++index)
            {
                if (!mem.Encode(bp.Targets[index].Target) || !mem.Encode(bp.Targets[index].RemainingPathIndex))
                {
                    return false;
                }
            }
            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out RelativePathElement rp)
        {
            rp = null;
            if (!mem.Decode(out NodeId id) || !mem.Decode(out bool v1) || !mem.Decode(out bool v2))
            {
                return false;
            }

            if (!mem.Decode(out QualifiedName qn))
            {
                return false;
            }

            try
            {
                rp = new RelativePathElement(id, v1, v2, qn);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, RelativePathElement rp)
        {
            return mem.Encode(rp.ReferenceTypeId) && mem.Encode(rp.IsInverse) && (mem.Encode(rp.IncludeSubtypes) && mem.Encode(rp.TargetName));
        }

        public static bool Decode(this MemoryBuffer mem, out BrowsePath bp)
        {
            bp = null;
            if (!mem.Decode(out NodeId id) || !mem.Decode(out uint v))
            {
                return false;
            }

            RelativePathElement[] RelativePath = new RelativePathElement[(int)v];
            for (uint index = 0; index < v; ++index)
            {
                if (!mem.Decode(out RelativePath[(int)index]))
                {
                    return false;
                }
            }
            try
            {
                bp = new BrowsePath(id, RelativePath);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowsePath bp)
        {
            if (!mem.Encode(bp.StartingNode) || !mem.Encode((uint)bp.RelativePath.Length))
            {
                return false;
            }

            for (int index = 0; index < bp.RelativePath.Length; ++index)
            {
                if (!mem.Encode(bp.RelativePath[index]))
                {
                    return false;
                }
            }
            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemModifyResult mr)
        {
            mr = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out double v2) || !mem.Decode(out uint v3))
            {
                return false;
            }

            if (!mem.Decode(out ExtensionObject Filter))
            {
                return false;
            }

            try
            {
                mr = new MonitoredItemModifyResult((StatusCode)v1, v2, v3, Filter);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemModifyResult mr)
        {
            return mem.Encode((uint)mr.StatusCode) && mem.Encode(mr.RevisedSamplingInterval) && (mem.Encode(mr.RevisedQueueSize) && mem.Encode(mr.Filter));
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemCreateResult cr)
        {
            cr = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out uint v2) || (!mem.Decode(out double v3) || !mem.Decode(out uint v4)))
            {
                return false;
            }

            if (!mem.Decode(out ExtensionObject Filter))
            {
                return false;
            }

            try
            {
                cr = new MonitoredItemCreateResult((StatusCode)v1, v2, v3, v4, Filter);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemCreateResult cr)
        {
            return mem.Encode((uint)cr.StatusCode) && mem.Encode(cr.MonitoredItemId) && (mem.Encode(cr.RevisedSamplingInterval) && mem.Encode(cr.RevisedQueueSize)) && mem.Encode(cr.Filter);
        }

        public static bool Decode(this MemoryBuffer mem, out ContentFilterElement cfe)
        {
            cfe = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out uint v2))
            {
                return false;
            }

            FilterOperand[] Operands = new FilterOperand[(int)v2];
            for (uint index = 0; index < v2; ++index)
            {
                if (!mem.Decode(out NodeId _) || !mem.Decode(out byte _) || !mem.Decode(out uint _))
                {
                    return false;
                }

                if (!mem.VariantDecode(out object res))
                {
                    return false;
                }

                Operands[(int)index] = new LiteralOperand(res);
            }
            try
            {
                cfe = new ContentFilterElement((FilterOperator)v1, Operands);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ContentFilterElement cfe)
        {
            if (!mem.Encode((uint)cfe.Operator) || !mem.Encode((uint)cfe.Operands.Length))
            {
                return false;
            }

            for (int index = 0; index < cfe.Operands.Length; ++index)
            {
                NodeId id = new NodeId(597U);
                byte v1 = 1;
                uint v2 = (uint)mem.VariantCodingSize((cfe.Operands[index] as LiteralOperand).Value);
                if (!mem.Encode(id) || !mem.Encode(v1) || (!mem.Encode(v2) || !mem.VariantEncode((cfe.Operands[index] as LiteralOperand).Value)))
                {
                    return false;
                }
            }
            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out EventFilter filter, bool includeType)
        {
            filter = null;
            if (includeType)
            {
                if (!mem.Decode(out NodeId id) || !mem.Decode(out byte v))
                {
                    return false;
                }

                if (id.EqualsNumeric(0, 0U) && v == 0)
                {
                    return true;
                }

                if (!id.EqualsNumeric(0, 727U) || v != 1 || !mem.Decode(out uint _))
                {
                    return false;
                }
            }
            if (!mem.Decode(out uint v1))
            {
                return false;
            }

            SimpleAttributeOperand[] SelectClauses = null;
            if (v1 != uint.MaxValue)
            {
                SelectClauses = new SimpleAttributeOperand[(int)v1];
                for (uint index1 = 0; index1 < v1; ++index1)
                {
                    if (!mem.Decode(out NodeId id) || !mem.Decode(out uint v2))
                    {
                        return false;
                    }

                    QualifiedName[] BrowsePath = new QualifiedName[(int)v2];
                    for (uint index2 = 0; index2 < v2; ++index2)
                    {
                        if (!mem.Decode(out BrowsePath[(int)index2]))
                        {
                            return false;
                        }
                    }
                    if (!mem.Decode(out uint v3))
                    {
                        return false;
                    }

                    if (!mem.DecodeUAString(out string str))
                    {
                        return false;
                    }

                    try
                    {
                        SelectClauses[(int)index1] = new SimpleAttributeOperand(id, BrowsePath, (NodeAttribute)v3, str);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            if (!mem.Decode(out uint v4))
            {
                return false;
            }

            ContentFilterElement[] ContentFilters = null;
            if (v4 != uint.MaxValue)
            {
                ContentFilters = new ContentFilterElement[(int)v4];
                for (uint index = 0; index < v4; ++index)
                {
                    if (!mem.Decode(out ContentFilters[(int)index]))
                    {
                        return false;
                    }
                }
            }
            try
            {
                filter = new EventFilter(SelectClauses, ContentFilters);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, EventFilter filter, bool includeType)
        {
            if (filter == null)
            {
                return !includeType || mem.Encode(NodeId.Zero) && mem.Encode((byte)0);
            }

            if (includeType && (!mem.Encode(new NodeId(727U)) || !mem.Encode((byte)1)))
            {
                return false;
            }

            uint v = 0;
            int position1 = mem.Position;
            if (includeType && !mem.Encode(v))
            {
                return false;
            }

            if (filter.SelectClauses == null)
            {
                if (!mem.Encode(uint.MaxValue))
                {
                    return false;
                }
            }
            else
            {
                if (!mem.Encode((uint)filter.SelectClauses.Length))
                {
                    return false;
                }

                for (int index1 = 0; index1 < filter.SelectClauses.Length; ++index1)
                {
                    if (!mem.Encode(filter.SelectClauses[index1].TypeDefinitionId) || !mem.Encode((uint)filter.SelectClauses[index1].BrowsePath.Length))
                    {
                        return false;
                    }

                    for (int index2 = 0; index2 < filter.SelectClauses[index1].BrowsePath.Length; ++index2)
                    {
                        if (!mem.Encode(filter.SelectClauses[index1].BrowsePath[index2]))
                        {
                            return false;
                        }
                    }
                    if (!mem.Encode((uint)filter.SelectClauses[index1].AttributeId) || !mem.EncodeUAString(filter.SelectClauses[index1].IndexRange))
                    {
                        return false;
                    }
                }
            }
            if (filter.ContentFilters == null)
            {
                if (!mem.Encode(uint.MaxValue))
                {
                    return false;
                }
            }
            else
            {
                if (!mem.Encode((uint)filter.ContentFilters.Length))
                {
                    return false;
                }

                for (int index = 0; index < filter.ContentFilters.Length; ++index)
                {
                    if (!mem.Encode(filter.ContentFilters[index]))
                    {
                        return false;
                    }
                }
            }
            if (includeType)
            {
                int position2 = mem.Position;
                mem.Position = position1;
                if (!mem.Encode(v))
                {
                    mem.Position = position2;
                    return false;
                }
                mem.Position = position2;
            }
            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoringParameters para)
        {
            para = null;
            if (!mem.Decode(out uint v1) || !mem.Decode(out double v2) || (!mem.Decode(out EventFilter filter, true) || !mem.Decode(out uint v3)))
            {
                return false;
            }

            if (!mem.Decode(out bool v4))
            {
                return false;
            }

            try
            {
                para = new MonitoringParameters(v1, v2, filter, v3, v4);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoringParameters para)
        {
            return mem.Encode(para.ClientHandle) && mem.Encode(para.SamplingInterval) && (mem.Encode(para.Filter, true) && mem.Encode(para.QueueSize)) && mem.Encode(para.DiscardOldest);
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemCreateRequest cr)
        {
            cr = null;
            if (!mem.Decode(out ReadValueId rv) || !mem.Decode(out uint v))
            {
                return false;
            }

            if (!mem.Decode(out MonitoringParameters para))
            {
                return false;
            }

            try
            {
                cr = new MonitoredItemCreateRequest(rv, (MonitoringMode)v, para);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemCreateRequest cr)
        {
            return mem.Encode(cr.ItemToMonitor) && mem.Encode((uint)cr.Mode) && mem.Encode(cr.RequestedParameters);
        }

        public static bool Decode(this MemoryBuffer mem, out ReferenceDescription rd)
        {
            rd = null;
            if (!mem.Decode(out NodeId id1) || !mem.Decode(out bool v1) || (!mem.Decode(out NodeId id2) || !mem.Decode(out QualifiedName qn)) || (!mem.Decode(out LocalizedText ad) || !mem.Decode(out int v2)))
            {
                return false;
            }

            if (!mem.Decode(out NodeId id3))
            {
                return false;
            }

            try
            {
                rd = new ReferenceDescription(id1, v1, id2, qn, ad, (NodeClass)v2, id3);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ReferenceDescription rd)
        {
            return mem.Encode(rd.ReferenceTypeId) && mem.Encode(rd.IsForward) && (mem.Encode(rd.TargetId) && mem.Encode(rd.BrowseName)) && (mem.Encode(rd.DisplayName) && mem.Encode((int)rd.NodeClass) && mem.Encode(rd.TypeDefinition));
        }

        public static bool Decode(this MemoryBuffer mem, out BrowseDescription bd)
        {
            bd = null;
            if (!mem.Decode(out NodeId id1) || !mem.Decode(out uint v1) || (!mem.Decode(out NodeId id2) || !mem.Decode(out bool v2)) || !mem.Decode(out uint v3))
            {
                return false;
            }

            if (!mem.Decode(out uint v4))
            {
                return false;
            }

            try
            {
                bd = new BrowseDescription(id1, (BrowseDirection)v1, id2, v2, v3, (BrowseResultMask)v4);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowseDescription bd)
        {
            return mem.Encode(bd.Id) && mem.Encode((uint)bd.Direction) && (mem.Encode(bd.ReferenceType) && mem.Encode(bd.IncludeSubtypes)) && (mem.Encode(bd.NodeClassMask) && mem.Encode((uint)bd.ResultMask));
        }

        public static bool Decode(this MemoryBuffer mem, out DataValue dv)
        {
            dv = null;
            object res = null;
            uint v1 = 0;
            long v2 = 0;
            long v3 = 0;
            bool flag1 = false;
            bool flag2 = false;
            bool flag3 = false;
            if (!mem.Decode(out byte v4) || (v4 & 1U) > 0U && !mem.VariantDecode(out res))
            {
                return false;
            }

            if ((v4 & 2U) > 0U)
            {
                if (!mem.Decode(out v1))
                {
                    return false;
                }

                flag1 = true;
            }
            if ((v4 & 4U) > 0U)
            {
                if (!mem.Decode(out v2))
                {
                    return false;
                }

                flag2 = true;
            }
            if ((v4 & 8U) > 0U)
            {
                if (!mem.Decode(out v3))
                {
                    return false;
                }

                flag3 = true;
            }
            try
            {
                dv = new DataValue(res, flag1 ? new StatusCode?((StatusCode)v1) : new StatusCode?(), flag2 ? new DateTime?(DateTime.FromFileTimeUtc(v2)) : new DateTime?(), flag3 ? new DateTime?(DateTime.FromFileTimeUtc(v3)) : new DateTime?());
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, DataValue dv)
        {
            int num1 = 0 + mem.CodingSize(dv.GetEncodingMask());
            if (dv.Value != null)
            {
                num1 += mem.VariantCodingSize(dv.Value);
            }

            uint? statusCode = dv.StatusCode;
            if (statusCode.HasValue)
            {
                int num2 = num1;
                MemoryBuffer memoryBuffer = mem;
                statusCode = dv.StatusCode;
                int num3 = (int)statusCode.Value;
                int num4 = memoryBuffer.CodingSize((uint)num3);
                num1 = num2 + num4;
            }
            DateTime? nullable = dv.SourceTimestamp;
            DateTime dateTime;
            if (nullable.HasValue)
            {
                int num2 = num1;
                MemoryBuffer memoryBuffer = mem;
                nullable = dv.SourceTimestamp;
                dateTime = nullable.Value;
                long fileTimeUtc = dateTime.ToFileTimeUtc();
                int num3 = memoryBuffer.CodingSize(fileTimeUtc);
                num1 = num2 + num3;
            }
            nullable = dv.ServerTimestamp;
            if (nullable.HasValue)
            {
                int num2 = num1;
                MemoryBuffer memoryBuffer = mem;
                nullable = dv.ServerTimestamp;
                dateTime = nullable.Value;
                long fileTimeUtc = dateTime.ToFileTimeUtc();
                int num3 = memoryBuffer.CodingSize(fileTimeUtc);
                num1 = num2 + num3;
            }
            return num1;
        }

        public static bool Encode(this MemoryBuffer mem, DataValue dv)
        {
            return mem.Encode(dv.GetEncodingMask()) && (dv.Value == null || mem.VariantEncode(dv.Value)) && (!dv.StatusCode.HasValue || mem.Encode(dv.StatusCode.Value)) && ((!dv.SourceTimestamp.HasValue || mem.Encode(dv.SourceTimestamp.Value.ToFileTimeUtc())) && (!dv.ServerTimestamp.HasValue || mem.Encode(dv.ServerTimestamp.Value.ToFileTimeUtc())));
        }

        public static bool Decode(this MemoryBuffer mem, out ReadValueId rv)
        {
            rv = null;
            if (!mem.Decode(out NodeId id) || !mem.Decode(out uint v) || !mem.DecodeUAString(out string str))
            {
                return false;
            }

            if (!mem.Decode(out QualifiedName qn))
            {
                return false;
            }

            try
            {
                rv = new ReadValueId(id, (NodeAttribute)v, str, qn);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ReadValueId rv)
        {
            return mem.Encode(rv.NodeId) && mem.Encode((uint)rv.AttributeId) && (mem.EncodeUAString(rv.IndexRange) && mem.Encode(rv.DataEncoding));
        }

        public static bool Decode(this MemoryBuffer mem, out EndpointDescription ep)
        {
            ep = null;
            List<UserTokenPolicy> userTokenPolicyList = new List<UserTokenPolicy>();
            if (!mem.DecodeUAString(out string str1) || !mem.Decode(out ApplicationDescription ad) || (!mem.DecodeUAByteString(out byte[] str2) || !mem.Decode(out uint v1)) || (!mem.DecodeUAString(out string str3) || !mem.Decode(out uint v2)))
            {
                return false;
            }

            if (v2 != uint.MaxValue)
            {
                for (uint index = 0; index < v2; ++index)
                {
                    if (!mem.DecodeUAString(out string str4) || !mem.Decode(out uint v3) || (!mem.DecodeUAString(out string str5) || !mem.DecodeUAString(out string str6)))
                    {
                        return false;
                    }

                    if (!mem.DecodeUAString(out string str7))
                    {
                        return false;
                    }

                    try
                    {
                        userTokenPolicyList.Add(new UserTokenPolicy(str4, (UserTokenType)v3, str5, str6, str7));
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            if (!mem.DecodeUAString(out string str8))
            {
                return false;
            }

            if (!mem.Decode(out byte v4))
            {
                return false;
            }

            try
            {
                ep = new EndpointDescription(str1, ad, str2, (MessageSecurityMode)v1, str3, userTokenPolicyList.ToArray(), str8, v4);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, EndpointDescription ep)
        {
            if (!mem.EncodeUAString(ep.EndpointUrl) || !mem.Encode(ep.Server) || (!mem.EncodeUAByteString(ep.ServerCertificate ?? new byte[0]) || !mem.Encode((uint)ep.SecurityMode) || !mem.EncodeUAString(ep.SecurityPolicyUri)))
            {
                return false;
            }

            if (ep.UserIdentityTokens == null)
            {
                if (!mem.Encode(0U))
                {
                    return false;
                }
            }
            else
            {
                if (!mem.Encode((uint)ep.UserIdentityTokens.Length))
                {
                    return false;
                }

                for (uint index = 0; index < ep.UserIdentityTokens.Length; ++index)
                {
                    if (!mem.EncodeUAString(ep.UserIdentityTokens[(int)index].PolicyId) || !mem.Encode((uint)ep.UserIdentityTokens[(int)index].TokenType) || (!mem.EncodeUAString(ep.UserIdentityTokens[(int)index].IssuedTokenType) || !mem.EncodeUAString(ep.UserIdentityTokens[(int)index].IssuerEndpointUrl)) || !mem.EncodeUAString(ep.UserIdentityTokens[(int)index].SecurityPolicyUri))
                    {
                        return false;
                    }
                }
            }
            return mem.EncodeUAString(ep.TransportProfileUri) && mem.Encode(ep.SecurityLevel);
        }

        public static bool Decode(this MemoryBuffer mem, out ApplicationDescription ad)
        {
            ad = null;
            if (!mem.DecodeUAString(out string str1) || !mem.DecodeUAString(out string str2) || (!mem.Decode(out LocalizedText ad1) || !mem.Decode(out uint v)) || (!mem.DecodeUAString(out string str3) || !mem.DecodeUAString(out string str4)))
            {
                return false;
            }

            if (!mem.DecodeUAString(out string[] table))
            {
                return false;
            }

            try
            {
                ad = new ApplicationDescription(str1, str2, ad1, (ApplicationType)v, str3, str4, table);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ApplicationDescription ad)
        {
            return mem.EncodeUAString(ad.ApplicationUri) && mem.EncodeUAString(ad.ProductUri) && (mem.Encode(ad.ApplicationName) && mem.Encode((uint)ad.Type)) && (mem.EncodeUAString(ad.GatewayServerUri) && mem.EncodeUAString(ad.DiscoveryProfileUri) && mem.EncodeUAString(ad.DiscoveryUrls));
        }

        public static bool Encode(
          this MemoryBuffer mem,
          ApplicationDescription ad,
          string[] DiscoveryUrls)
        {
            return mem.EncodeUAString(ad.ApplicationUri) && mem.EncodeUAString(ad.ProductUri) && (mem.Encode(ad.ApplicationName) && mem.Encode((uint)ad.Type)) && (mem.EncodeUAString(ad.GatewayServerUri) && mem.EncodeUAString(ad.DiscoveryProfileUri) && mem.EncodeUAString(DiscoveryUrls));
        }

        public static bool Decode(this MemoryBuffer mem, out QualifiedName qn)
        {
            qn = new QualifiedName();
            if (!mem.Decode(out ushort v) || !mem.DecodeUAString(out string str))
            {
                return false;
            }

            qn = new QualifiedName(v, str);
            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, QualifiedName qn)
        {
            return mem.CodingSize(qn.NamespaceIndex) + mem.CodingSizeUAString(qn.Name);
        }

        public static bool Encode(this MemoryBuffer mem, QualifiedName qn)
        {
            return mem.Encode(qn.NamespaceIndex) && mem.EncodeUAString(qn.Name);
        }

        public static bool Decode(this MemoryBuffer mem, out LocalizedText ad)
        {
            ad = null;
            string str1 = string.Empty;
            string str2 = string.Empty;
            if (!mem.Decode(out byte v) || (v & 1U) > 0U && !mem.DecodeUAString(out str1) || (v & 2U) > 0U && !mem.DecodeUAString(out str2))
            {
                return false;
            }

            ad = new LocalizedText(str1, str2);
            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, LocalizedText ad)
        {
            int num = mem.CodingSize((byte)0);
            if (!string.IsNullOrEmpty(ad.Locale))
            {
                num += mem.CodingSizeUAString(ad.Locale);
            }

            if (!string.IsNullOrEmpty(ad.Text))
            {
                num += mem.CodingSizeUAString(ad.Text);
            }

            return num;
        }

        public static bool Encode(this MemoryBuffer mem, LocalizedText ad)
        {
            byte v = 0;
            if (!string.IsNullOrEmpty(ad.Locale))
            {
                v |= 1;
            }

            if (!string.IsNullOrEmpty(ad.Text))
            {
                v |= 2;
            }

            return mem.Encode(v) && (string.IsNullOrEmpty(ad.Locale) || mem.EncodeUAString(ad.Locale)) && (string.IsNullOrEmpty(ad.Text) || mem.EncodeUAString(ad.Text));
        }

        public static bool Decode(this MemoryBuffer mem, out ResponseHeader resp)
        {
            resp = null;
            if (!mem.Decode(out ulong v1) || !mem.Decode(out uint v2) || (!mem.Decode(out uint v3) || !mem.Decode(out byte v4)) || (!mem.DecodeUAString(out string[] table) || !mem.Decode(out ExtensionObject extensionObject)))
            {
                return false;
            }

            resp = new ResponseHeader();
            try
            {
                resp.Timestamp = DateTimeOffset.FromFileTime((long)v1);
            }
            catch
            {
                resp.Timestamp = DateTimeOffset.MinValue;
            }
            resp.RequestHandle = v2;
            resp.ServiceResult = v3;
            resp.ServiceDiagnosticsMask = v4;
            resp.StringTable = table;
            resp.AdditionalHeader = extensionObject;
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ResponseHeader resp)
        {
            return mem.Encode(resp.Timestamp.ToFileTime()) && mem.Encode(resp.RequestHandle) && (mem.Encode(resp.ServiceResult) && mem.Encode((byte)0)) && (mem.EncodeUAString(resp.StringTable) && mem.Encode(resp.AdditionalHeader));
        }

        public static bool Decode(this MemoryBuffer mem, out RequestHeader req)
        {
            req = null;
            if (!mem.Decode(out NodeId id) || !mem.Decode(out ulong v1) || (!mem.Decode(out uint v2) || !mem.Decode(out uint v3)) || (!mem.DecodeUAString(out string str) || !mem.Decode(out uint v4) || !mem.Decode(out ExtensionObject extensionObject)))
            {
                return false;
            }

            req = new RequestHeader();
            try
            {
                req.Timestamp = DateTime.FromFileTimeUtc((long)v1);
            }
            catch
            {
                req.Timestamp = DateTime.MinValue;
            }
            req.AuthToken = id;
            req.RequestHandle = v2;
            req.ReturnDiagnostics = v3;
            req.AuditEntryId = str;
            req.TimeoutHint = v4;
            req.AdditionalHeader = extensionObject;
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, RequestHeader req)
        {
            return mem.Encode(req.AuthToken) && mem.Encode((ulong)req.Timestamp.ToFileTimeUtc()) && (mem.Encode(req.RequestHandle) && mem.Encode(req.ReturnDiagnostics)) && (mem.EncodeUAString(req.AuditEntryId) && mem.Encode(req.TimeoutHint) && mem.Encode(req.AdditionalHeader));
        }

        public static int CodingSize(this MemoryBuffer mem, ExtensionObject obj)
        {
            int num1 = 0;
            if (obj == null)
            {
                return mem.CodingSize(NodeId.Zero) + mem.CodingSize((byte)0);
            }

            int num2 = num1 + mem.CodingSize(obj.TypeId) + mem.CodingSize((byte)0);
            return obj.Body == null ? num2 : num2 + mem.CodingSizeUAByteString(obj.Body);
        }

        public static bool Decode(this MemoryBuffer mem, out ExtensionObject obj)
        {
            obj = new ExtensionObject();
            if (!mem.Decode(out NodeId id))
            {
                return false;
            }

            obj.TypeId = id;
            if (!mem.Decode(out byte v))
            {
                return false;
            }

            if (v != 1)
            {
                return true;
            }

            if (!mem.DecodeUAByteString(out byte[] str))
            {
                return false;
            }

            obj.Body = str;
            MemoryBuffer mem1 = new MemoryBuffer(str);
            switch (obj.TypeId.NumericIdentifier)
            {
                case 354:
                    ObjectAttributes objectAttributes;
                    if (!mem1.Decode(out objectAttributes))
                    {
                        return false;
                    }

                    obj.Payload = objectAttributes;
                    break;
                case 357:
                    VariableAttributes variableAttributes;
                    if (!mem1.Decode(out variableAttributes))
                    {
                        return false;
                    }

                    obj.Payload = variableAttributes;
                    break;
                case 363:
                    ObjectTypeAttributes objectTypeAttributes;
                    if (!mem1.Decode(out objectTypeAttributes))
                    {
                        return false;
                    }

                    obj.Payload = objectTypeAttributes;
                    break;
                case 366:
                    VariableTypeAttributes variableTypeAttributes;
                    if (!mem1.Decode(out variableTypeAttributes))
                    {
                        return false;
                    }

                    obj.Payload = variableTypeAttributes;
                    break;
            }
            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ExtensionObject obj)
        {
            if (obj == null)
            {
                return mem.Encode(NodeId.Zero) && mem.Encode((byte)0);
            }

            if (obj.Payload != null)
            {
                MemoryBuffer mem1 = new MemoryBuffer(mem.Capacity);
                UAConst NumericIdentifier = 0;
                switch (obj.Payload)
                {
                    case ObjectAttributes objectAttributes:
                        NumericIdentifier = UAConst.ObjectAttributes_Encoding_DefaultBinary;
                        if (!mem1.Encode(objectAttributes))
                        {
                            return false;
                        }

                        break;
                    case ObjectTypeAttributes objectTypeAttributes:
                        NumericIdentifier = UAConst.ObjectTypeAttributes_Encoding_DefaultBinary;
                        if (!mem1.Encode(objectTypeAttributes))
                        {
                            return false;
                        }

                        break;
                    case VariableAttributes variableAttributes:
                        NumericIdentifier = UAConst.VariableAttributes_Encoding_DefaultBinary;
                        if (!mem1.Encode(variableAttributes))
                        {
                            return false;
                        }

                        break;
                    case VariableTypeAttributes variableTypeAttributes:
                        NumericIdentifier = UAConst.VariableTypeAttributes_Encoding_DefaultBinary;
                        if (!mem1.Encode(variableTypeAttributes))
                        {
                            return false;
                        }

                        break;
                }
                if (NumericIdentifier > 0)
                {
                    obj.TypeId = new NodeId(NumericIdentifier);
                    obj.Body = new byte[mem1.Position];
                    Array.Copy(mem1.Buffer, obj.Body, obj.Body.Length);
                }
            }
            if (!mem.Encode(obj.TypeId))
            {
                return false;
            }

            if (obj.Body == null)
            {
                return mem.Encode((byte)0);
            }

            return mem.Encode((byte)1) && mem.EncodeUAByteString(obj.Body);
        }

        public static bool Decode(this MemoryBuffer mem, out NodeId id)
        {
            id = null;
            if (!mem.Decode(out byte v1))
            {
                return false;
            }

            switch (v1)
            {
                case 0:
                    byte v2;
                    if (!mem.Decode(out v2))
                    {
                        return false;
                    }

                    id = new NodeId(0, v2);
                    return true;
                case 1:
                    byte v3;
                    ushort v4;
                    if (!mem.Decode(out v3) || !mem.Decode(out v4))
                    {
                        return false;
                    }

                    id = new NodeId(v3, v4);
                    return true;
                case 2:
                    ushort v5;
                    uint v6;
                    if (!mem.Decode(out v5) || !mem.Decode(out v6))
                    {
                        return false;
                    }

                    id = new NodeId(v5, v6);
                    return true;
                case 3:
                    ushort v7;
                    string str1;
                    if (!mem.Decode(out v7) || !mem.DecodeUAString(out str1))
                    {
                        return false;
                    }

                    id = new NodeId(v7, str1);
                    return true;
                case 4:
                    ushort v8;
                    byte[] str2;
                    if (!mem.Decode(out v8) || !mem.DecodeUAGuidByteString(out str2))
                    {
                        return false;
                    }

                    id = new NodeId(v8, str2, NodeIdNetType.Guid);
                    return true;
                case 5:
                    ushort v9;
                    byte[] str3;
                    if (!mem.Decode(out v9) || !mem.DecodeUAByteString(out str3))
                    {
                        return false;
                    }

                    id = new NodeId(v9, str3, NodeIdNetType.ByteString);
                    return true;
                default:
                    throw new Exception();
            }
        }

        public static bool Encode(this MemoryBuffer mem, NodeId id)
        {
            if (id == null)
            {
                return mem.Encode(NodeId.Zero);
            }

            switch (id.IdType)
            {
                case NodeIdNetType.Numeric:
                    if (id.NamespaceIndex == 0 && id.NumericIdentifier <= byte.MaxValue)
                    {
                        if (!mem.Encode((byte)0) || !mem.Encode((byte)id.NumericIdentifier))
                        {
                            return false;
                        }

                        break;
                    }
                    if (id.NamespaceIndex <= byte.MaxValue && id.NumericIdentifier <= ushort.MaxValue)
                    {
                        if (!mem.Encode((byte)1) || !mem.Encode((byte)id.NamespaceIndex) || !mem.Encode((ushort)id.NumericIdentifier))
                        {
                            return false;
                        }

                        break;
                    }
                    if (!mem.Encode((byte)2) || !mem.Encode(id.NamespaceIndex) || !mem.Encode(id.NumericIdentifier))
                    {
                        return false;
                    }

                    break;
                case NodeIdNetType.String:
                    if (!mem.Encode((byte)3) || !mem.Encode(id.NamespaceIndex) || !mem.EncodeUAString(id.StringIdentifier))
                    {
                        return false;
                    }

                    break;
                case NodeIdNetType.Guid:
                    if (!mem.Encode((byte)4) || !mem.Encode(id.NamespaceIndex) || !mem.EncodeUAGuidByteString(id.ByteStringIdentifier))
                    {
                        return false;
                    }

                    break;
                case NodeIdNetType.ByteString:
                    if (!mem.Encode((byte)5) || !mem.Encode(id.NamespaceIndex) || !mem.EncodeUAByteString(id.ByteStringIdentifier))
                    {
                        return false;
                    }

                    break;
                default:
                    throw new Exception();
            }
            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, NodeId id)
        {
            switch (id.IdType)
            {
                case NodeIdNetType.Numeric:
                    if (id.NamespaceIndex == 0 && id.NumericIdentifier <= byte.MaxValue)
                    {
                        return 2;
                    }

                    return id.NamespaceIndex <= byte.MaxValue && id.NumericIdentifier <= ushort.MaxValue ? 4 : 7;
                case NodeIdNetType.String:
                    return 3 + mem.CodingSizeUAString(id.StringIdentifier);
                default:
                    throw new Exception();
            }
        }

        public static bool EncodeUAByteString(this MemoryBuffer mem, byte[] str)
        {
            if (str == null)
            {
                return mem.Encode(uint.MaxValue);
            }

            if (!mem.Encode((uint)str.Length))
            {
                return false;
            }

            if ((uint)str.Length <= 0U)
            {
                return true;
            }

            return mem.EnsureAvailable(str.Length, true) && mem.Append(str, str.Length);
        }

        public static bool DecodeUAByteString(this MemoryBuffer mem, out byte[] str)
        {
            str = null;
            if (!mem.Decode(out uint v))
            {
                return false;
            }

            if (v == uint.MaxValue)
            {
                return true;
            }

            if (!mem.EnsureAvailable((int)v, true))
            {
                return false;
            }

            if (v == 0U)
            {
                str = new byte[0];
                return true;
            }
            str = new byte[(int)v];
            Array.Copy(mem.Buffer, mem.Position, str, 0L, v);
            mem.Position += (int)v;
            return true;
        }

        public static bool EncodeUAGuidByteString(this MemoryBuffer mem, byte[] str)
        {
            return str != null && str.Length == 16 && mem.EnsureAvailable(str.Length, true) && mem.Append(str, str.Length);
        }

        public static bool DecodeUAGuidByteString(this MemoryBuffer mem, out byte[] str)
        {
            uint num = 16;
            str = null;
            if (!mem.EnsureAvailable((int)num, true))
            {
                return false;
            }

            str = new byte[(int)num];
            Array.Copy(mem.Buffer, mem.Position, str, 0L, num);
            mem.Position += (int)num;
            return true;
        }

        public static bool EncodeUAString(this MemoryBuffer mem, string[] table)
        {
            if (table == null)
            {
                if (!mem.Encode(0U))
                {
                    return false;
                }
            }
            else
            {
                if (!mem.Encode((uint)table.Length))
                {
                    return false;
                }

                for (int index = 0; index < table.Length; ++index)
                {
                    if (!mem.EncodeUAString(table[index]))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static bool DecodeUAString(this MemoryBuffer mem, out string[] table)
        {
            table = null;
            if (!mem.Decode(out uint v))
            {
                return false;
            }

            if (v == uint.MaxValue)
            {
                return true;
            }

            table = new string[(int)v];
            for (int index = 0; index < v; ++index)
            {
                mem.DecodeUAString(out table[index]);
            }

            return true;
        }

        public static int CodingSizeUAByteString(this MemoryBuffer mem, byte[] str)
        {
            return str == null ? mem.CodingSize(0U) : mem.CodingSize(0U) + str.Length;
        }

        public static int CodingSizeUAGuidByteString(this MemoryBuffer mem, byte[] str)
        {
            return str == null ? 0 : str.Length;
        }

        public static int CodingSizeUAString(this MemoryBuffer mem, string str)
        {
            return str == null ? mem.CodingSize(0U) : mem.CodingSize(0U) + str.Length;
        }

        public static bool EncodeUAString(this MemoryBuffer mem, string str)
        {
            if (str == null)
            {
                return mem.Encode(uint.MaxValue);
            }

            byte[] bytes = Encoding.UTF8.GetBytes(str);
            if (!mem.Encode((uint)bytes.Length))
            {
                return false;
            }

            if (str.Length <= 0)
            {
                return true;
            }

            return mem.EnsureAvailable(bytes.Length, true) && mem.Append(bytes, bytes.Length);
        }

        public static bool DecodeUAString(this MemoryBuffer mem, out string str)
        {
            str = null;
            if (!mem.Decode(out uint v))
            {
                return false;
            }

            if (v == uint.MaxValue)
            {
                return true;
            }

            byte[] bytes = new byte[(int)v];
            if (!mem.EnsureAvailable((int)v, true))
            {
                return false;
            }

            if (v == 0U)
            {
                str = string.Empty;
                return true;
            }
            Array.Copy(mem.Buffer, mem.Position, bytes, 0L, v);
            mem.Position += (int)v;
            str = Encoding.UTF8.GetString(bytes);
            return true;
        }
    }
}
