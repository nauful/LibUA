
// Type: LibUA.Server.Application



using LibUA.Core;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace LibUA.Server
{
    public partial class Application
    {
        protected ConcurrentDictionary<NodeId, LibUA.Core.Node> AddressSpaceTable;
        private HashSet<NodeId> internalAddressSpaceNodes;
        private Dictionary<NodeId, object> internalAddressSpaceValues;
        private readonly ReaderWriterLockSlim monitorMapRW;
        private readonly Dictionary<Application.ServerMonitorKey, List<MonitoredItem>> monitorMap;

        public virtual X509Certificate2 ApplicationCertificate
        {
            get
            {
                return null;
            }
        }

        public virtual RSACryptoServiceProvider ApplicationPrivateKey
        {
            get
            {
                return null;
            }
        }

        public Application()
        {
            this.AddressSpaceTable = new ConcurrentDictionary<NodeId, LibUA.Core.Node>();
            this.SetupDefaultAddressSpace();
            this.AddressSpaceTable[new NodeId(UAConst.BaseDataType)].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.DataTypesFolder), false));
            this.SetupInternalAddressSpace();
            this.monitorMapRW = new ReaderWriterLockSlim();
            this.monitorMap = new Dictionary<Application.ServerMonitorKey, List<MonitoredItem>>();
        }

        public virtual bool MonitorAdd(object session, MonitoredItem mi)
        {
            if (!this.AddressSpaceTable.TryGetValue(mi.ItemToMonitor.NodeId, out LibUA.Core.Node _) || !this.SessionHasPermissionToRead(session, mi.ItemToMonitor.NodeId))
            {
                return false;
            }

            Application.ServerMonitorKey key = new Application.ServerMonitorKey(mi.ItemToMonitor);
            try
            {
                this.monitorMapRW.EnterWriteLock();
                if (this.monitorMap.TryGetValue(key, out List<MonitoredItem> monitoredItemList))
                {
                    monitoredItemList.Add(mi);
                }
                else
                {
                    this.monitorMap.Add(key, new List<MonitoredItem>()
          {
            mi
          });
                }
            }
            finally
            {
                this.monitorMapRW.ExitWriteLock();
            }
            return true;
        }

        public virtual void MonitorRemove(object session, MonitoredItem mi)
        {
            Application.ServerMonitorKey key = new Application.ServerMonitorKey(mi.ItemToMonitor);
            try
            {
                this.monitorMapRW.EnterWriteLock();
                if (!this.monitorMap.TryGetValue(key, out List<MonitoredItem> monitoredItemList))
                {
                    return;
                }

                monitoredItemList.Remove(mi);
            }
            finally
            {
                this.monitorMapRW.ExitWriteLock();
            }
        }

        public virtual void MonitorNotifyDataChange(NodeId id, DataValue dv)
        {
            Application.ServerMonitorKey key = new Application.ServerMonitorKey(id, NodeAttribute.Value);
            try
            {
                this.monitorMapRW.EnterReadLock();
                if (!this.monitorMap.TryGetValue(key, out List<MonitoredItem> monitoredItemList))
                {
                    return;
                }

                for (int index = 0; index < monitoredItemList.Count; ++index)
                {
                    if (monitoredItemList[index].QueueData.Count >= monitoredItemList[index].QueueSize)
                    {
                        monitoredItemList[index].QueueOverflowed = true;
                    }
                    else
                    {
                        monitoredItemList[index].QueueData.Enqueue(dv);
                    }

                    if (monitoredItemList[index].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                    {
                        monitoredItemList[index].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                    }
                }
            }
            finally
            {
                this.monitorMapRW.ExitReadLock();
            }
        }

        public virtual void MonitorNotifyEvent(NodeId id, EventNotification ev)
        {
            Application.ServerMonitorKey key = new Application.ServerMonitorKey(id, NodeAttribute.EventNotifier);
            try
            {
                this.monitorMapRW.EnterReadLock();
                if (!this.monitorMap.TryGetValue(key, out List<MonitoredItem> monitoredItemList))
                {
                    return;
                }

                for (int index = 0; index < monitoredItemList.Count; ++index)
                {
                    if (monitoredItemList[index].QueueEvent.Count >= monitoredItemList[index].QueueSize)
                    {
                        monitoredItemList[index].QueueOverflowed = true;
                    }
                    else
                    {
                        monitoredItemList[index].QueueEvent.Enqueue(ev);
                    }

                    if (monitoredItemList[index].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                    {
                        monitoredItemList[index].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                    }
                }
            }
            finally
            {
                this.monitorMapRW.ExitReadLock();
            }
        }

        public virtual object SessionCreate(Application.SessionCreationInfo sessionInfo)
        {
            return null;
        }

        public virtual bool SessionValidateClientApplication(
          object session,
          ApplicationDescription clientApplicationDescription,
          byte[] clientCertificate,
          string sessionName)
        {
            return true;
        }

        public virtual bool SessionValidateClientUser(object session, object userIdentityToken)
        {
            return true;
        }

        public virtual bool SessionActivateClient(
          object session,
          SecurityPolicy securityPolicy,
          MessageSecurityMode messageSecurityMode,
          X509Certificate2 remoteCertificate)
        {
            return true;
        }

        public virtual void SessionRelease(object session)
        {
        }

        public virtual ApplicationDescription GetApplicationDescription(
          string endpointUrlHint)
        {
            return null;
        }

        public virtual IList<EndpointDescription> GetEndpointDescriptions(
          string endpointUrlHint)
        {
            return new List<EndpointDescription>();
        }

        protected virtual DataValue HandleReadRequestInternal(NodeId id)
        {
            return this.internalAddressSpaceValues.TryGetValue(id, out object obj) ? new DataValue(obj, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?()) : new DataValue(null, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
        }

        private void SetupInternalAddressSpace()
        {
            internalAddressSpaceNodes = new HashSet<NodeId>();
            foreach (var key in AddressSpaceTable.Keys) { internalAddressSpaceNodes.Add(key); }

            internalAddressSpaceValues = new Dictionary<NodeId, object>()
                {
                    { new NodeId(UAConst.Server_ServerArray), new string[0] },
                    { new NodeId(UAConst.Server_NamespaceArray), new string[]
                        {
                            "http://opcfoundation.org/UA/",
                            "http://quantensystems.com/uaSDK2",
                            "http://quantensystems.com/DemoServer"
                        }
                    },
                    { new NodeId(UAConst.Server_ServerStatus_State), (Int32)ServerState.Running },

                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerRead), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerWrite), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerMethodCall), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerBrowse), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerRegisterNodes), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerTranslateBrowsePathsToNodeIds), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerNodeManagement), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxMonitoredItemsPerCall), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadData), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateData), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadEvents), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateEvents), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerMethodCall), 100 },

                    { new NodeId(UAConst.Server_ServerStatus_StartTime), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_CurrentTime), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_SecondsTillShutdown), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductUri), "product" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ManufacturerName), "manufacturer" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductName), "product" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_SoftwareVersion), 1.0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildNumber), 1.0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildDate), 0 }
                };
        }

        public bool IsSubtypeOrEqual(NodeId target, NodeId parent)
        {
            if (target.Equals(parent) || parent.EqualsNumeric(0, 0U))
            {
                return true;
            }

            if (!this.AddressSpaceTable.TryGetValue(parent, out Node node))
            {
                return false;
            }

            for (int index = 0; index < node.References.Count; ++index)
            {
                ReferenceNode reference = node.References[index];
                if (!reference.IsInverse && reference.ReferenceType.EqualsNumeric(0, 45U) && this.IsSubtypeOrEqual(target, reference.Target))
                {
                    return true;
                }
            }
            return false;
        }

        public virtual StatusCode HandleTranslateBrowsePathRequest(
          object session,
          BrowsePath path,
          List<BrowsePathTarget> res)
        {
            if (!this.AddressSpaceTable.TryGetValue(path.StartingNode, out Node node1) || !this.SessionHasPermissionToRead(session, path.StartingNode))
            {
                return StatusCode.BadNodeIdUnknown;
            }

            for (int index1 = 0; index1 < path.RelativePath.Length; ++index1)
            {
                RelativePathElement relativePathElement = path.RelativePath[index1];
                ReferenceNode referenceNode = null;
                for (int index2 = 0; index2 < node1.References.Count; ++index2)
                {
                    ReferenceNode reference = node1.References[index2];
                    if (relativePathElement.IsInverse == reference.IsInverse && (relativePathElement.IncludeSubtypes || reference.ReferenceType.Equals(relativePathElement.ReferenceTypeId)) && ((!relativePathElement.IncludeSubtypes || this.IsSubtypeOrEqual(reference.ReferenceType, relativePathElement.ReferenceTypeId)) && (this.AddressSpaceTable.TryGetValue(reference.Target, out Node node2) && this.SessionHasPermissionToRead(session, reference.Target) && node2.BrowseName.Equals(relativePathElement.TargetName))))
                    {
                        referenceNode = node1.References[index2];
                        node1 = node2;
                        break;
                    }
                }
                if (referenceNode == null || node1 == null)
                {
                    res.Add(new BrowsePathTarget()
                    {
                        Target = node1.Id,
                        RemainingPathIndex = (uint)index1
                    });
                    return StatusCode.BadNoMatch;
                }
            }
            res.Add(new BrowsePathTarget()
            {
                Target = node1.Id,
                RemainingPathIndex = (uint)path.RelativePath.Length
            });
            return StatusCode.Good;
        }

        public virtual StatusCode HandleBrowseRequest(
          object session,
          BrowseDescription browseDesc,
          List<ReferenceDescription> results,
          int maxResults,
          ContinuationPointBrowse cont)
        {
            if (!this.AddressSpaceTable.TryGetValue(browseDesc.Id, out Node node1) || !this.SessionHasPermissionToRead(session, browseDesc.Id))
            {
                return StatusCode.BadNodeIdUnknown;
            }

            results.Clear();
            for (int index1 = cont.IsValid ? cont.Offset : 0; index1 < node1.References.Count; ++index1)
            {
                ReferenceNode reference = node1.References[index1];
                if ((browseDesc.Direction != BrowseDirection.Forward || !reference.IsInverse) && (browseDesc.Direction != BrowseDirection.Inverse || reference.IsInverse) && (browseDesc.IncludeSubtypes || reference.ReferenceType.Equals(browseDesc.ReferenceType)) && (!browseDesc.IncludeSubtypes || this.IsSubtypeOrEqual(reference.ReferenceType, browseDesc.ReferenceType)))
                {
                    if (results.Count == maxResults)
                    {
                        cont.Offset = index1;
                        cont.IsValid = true;
                        return StatusCode.GoodMoreData;
                    }
                    NodeId TypeDefinition = NodeId.Zero;
                    if (!this.AddressSpaceTable.TryGetValue(reference.Target, out Node node2) || !this.SessionHasPermissionToRead(session, reference.Target))
                    {
                        results.Add(new ReferenceDescription(reference.ReferenceType, !reference.IsInverse, reference.Target, new QualifiedName(), new LocalizedText(string.Empty), NodeClass.Unspecified, TypeDefinition));
                    }
                    else if (node2.References != null && (node2 is NodeObject || node2 is NodeVariable))
                    {
                        for (int index2 = 0; index2 < node2.References.Count; ++index2)
                        {
                            if (node2.References[index2].ReferenceType.EqualsNumeric(0, 40U))
                            {
                                TypeDefinition = node2.References[index2].Target;
                            }
                        }
                    }
                    results.Add(new ReferenceDescription(reference.ReferenceType, !reference.IsInverse, reference.Target, node2.BrowseName, node2.DisplayName, node2.GetNodeClass(), TypeDefinition));
                }
            }
            cont.IsValid = false;
            return StatusCode.Good;
        }

        public virtual uint[] HandleWriteRequest(object session, WriteValue[] writeValues)
        {
            uint[] numArray = new uint[writeValues.Length];
            for (int index = 0; index < writeValues.Length; ++index)
            {
                numArray[index] = 2151350272U;
            }

            return numArray;
        }

        public virtual uint HandleHistoryReadRequest(
          object session,
          object readDetails,
          HistoryReadValueId id,
          ContinuationPointHistory continuationPoint,
          List<DataValue> results,
          ref int? offsetContinueFit)
        {
            return 2151677952;
        }

        public virtual uint[] HandleHistoryUpdateRequest(object session, HistoryUpdateData[] updates)
        {
            uint[] numArray = new uint[updates.Length];
            for (int index = 0; index < updates.Length; ++index)
            {
                numArray[index] = 2151677952U;
            }

            return numArray;
        }

        public virtual uint HandleHistoryEventReadRequest(
          object session,
          object readDetails,
          HistoryReadValueId id,
          ContinuationPointHistory continuationPoint,
          List<object[]> results)
        {
            return 2151677952;
        }

        public virtual DataValue[] HandleReadRequest(
          object session,
          ReadValueId[] readValueIds)
        {
            DataValue[] dataValueArray = new DataValue[readValueIds.Length];
            for (int index = 0; index < readValueIds.Length; ++index)
            {
                if (!this.AddressSpaceTable.TryGetValue(readValueIds[index].NodeId, out Node node) || !this.SessionHasPermissionToRead(session, readValueIds[index].NodeId))
                {
                    dataValueArray[index] = new DataValue(null, new StatusCode?(StatusCode.BadNodeIdUnknown), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.Value)
                {
                    dataValueArray[index] = this.HandleReadRequestInternal(readValueIds[index].NodeId);
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.NodeId)
                {
                    dataValueArray[index] = new DataValue(node.Id, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.NodeClass)
                {
                    NodeClass nodeClass = node.GetNodeClass();
                    dataValueArray[index] = new DataValue((int)nodeClass, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.BrowseName)
                {
                    dataValueArray[index] = new DataValue(node.BrowseName, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.DisplayName)
                {
                    dataValueArray[index] = new DataValue(node.DisplayName, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.Description)
                {
                    dataValueArray[index] = new DataValue(node.Description, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.WriteMask)
                {
                    dataValueArray[index] = new DataValue(node.WriteMask, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.UserWriteMask)
                {
                    dataValueArray[index] = new DataValue(node.UserWriteMask, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.UserWriteMask)
                {
                    dataValueArray[index] = new DataValue(node.UserWriteMask, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.AccessRestrictions)
                {
                    dataValueArray[index] = new DataValue((ushort)0, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.IsAbstract && node is NodeReferenceType)
                {
                    dataValueArray[index] = new DataValue((node as NodeReferenceType).IsAbstract, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.Symmetric && node is NodeReferenceType)
                {
                    dataValueArray[index] = new DataValue((node as NodeReferenceType).IsSymmetric, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.InverseName && node is NodeReferenceType)
                {
                    dataValueArray[index] = new DataValue((node as NodeReferenceType).InverseName, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.ContainsNoLoops && node is NodeView)
                {
                    dataValueArray[index] = new DataValue((node as NodeView).ContainsNoLoops, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.EventNotifier && node is NodeView)
                {
                    dataValueArray[index] = new DataValue((node as NodeView).EventNotifier, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.EventNotifier && node is NodeObject)
                {
                    dataValueArray[index] = new DataValue((node as NodeObject).EventNotifier, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.DataType && node is NodeVariable)
                {
                    dataValueArray[index] = new DataValue((node as NodeVariable).DataType ?? new NodeId(UAConst.BaseDataType), new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.DataType && node is NodeVariableType)
                {
                    dataValueArray[index] = new DataValue((node as NodeVariableType).DataType ?? new NodeId(UAConst.BaseDataType), new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if ((readValueIds[index].AttributeId == NodeAttribute.AccessLevel || readValueIds[index].AttributeId == NodeAttribute.AccessLevelEx) && node is NodeVariable)
                {
                    dataValueArray[index] = new DataValue((byte)(node as NodeVariable).AccessLevel, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.UserAccessLevel && node is NodeVariable)
                {
                    dataValueArray[index] = new DataValue((byte)(node as NodeVariable).UserAccessLevel, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.Historizing && node is NodeVariable)
                {
                    dataValueArray[index] = new DataValue((node as NodeVariable).IsHistorizing, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.MinimumSamplingInterval && node is NodeVariable)
                {
                    dataValueArray[index] = new DataValue((node as NodeVariable).MinimumResamplingInterval, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.Executable && node is NodeMethod)
                {
                    dataValueArray[index] = new DataValue((node as NodeMethod).IsExecutable, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else if (readValueIds[index].AttributeId == NodeAttribute.UserExecutable && node is NodeMethod)
                {
                    dataValueArray[index] = new DataValue((node as NodeMethod).IsUserExecutable, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
                else
                {
                    int num = readValueIds[index].AttributeId != NodeAttribute.ValueRank ? 0 : (node is NodeVariable ? 1 : 0);
                    dataValueArray[index] = num == 0 ? new DataValue(null, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?()) : new DataValue((node as NodeVariable).ValueRank, new StatusCode?(StatusCode.Good), new DateTime?(), new DateTime?());
                }
            }
            return dataValueArray;
        }

        protected bool SessionHasPermissionToRead(object session, NodeId nodeId)
        {
            return true;
        }


        protected struct ServerMonitorKey : IEquatable<Application.ServerMonitorKey>
        {
            public NodeId NodeId;
            public NodeAttribute Attribute;

            public ServerMonitorKey(NodeId nodeId, NodeAttribute attribute)
            {
                this.NodeId = nodeId;
                this.Attribute = attribute;
            }

            public ServerMonitorKey(ReadValueId itemToMonitor)
              : this(itemToMonitor.NodeId, itemToMonitor.AttributeId)
            {
            }

            public override int GetHashCode()
            {
                return (int)((NodeAttribute)this.NodeId.GetHashCode() ^ this.Attribute);
            }

            public override bool Equals(object obj)
            {
                return obj is Application.ServerMonitorKey serverMonitorKey && (this.NodeId == serverMonitorKey.NodeId && this.Attribute == ((Application.ServerMonitorKey)obj).Attribute);
            }

            public bool Equals(Application.ServerMonitorKey other)
            {
                return this.NodeId.Equals(other.NodeId) && this.Attribute == other.Attribute;
            }
        }

        public struct SessionCreationInfo
        {
            public EndPoint Endpoint;
        }
    }
}
