# Create a OPC UA server application

## Master

The Master class manages the TCP endpoint, client connections and communication. It requires an application instance to provide server information to the clients and to handle the requests.

To initialize a instance you require to provide following information to the constructor.

``` csharp
var master = new Master(app, port, timeout, backlog, maxClients, logger[, maximumMessageSize]);
```

| Parameter              | Description                                                                                      | Sample value      |
|------------------------|--------------------------------------------------------------------------------------------------|-------------------|
| **app**                | Instance of an class deriving from and implementing abstract members of the `Application` class. | -                 |
| **port**               | TCP/IP port used to listen for client connections.                                               | 4840              |
| **timeout**            | **[obsolete]** Value is not used anymore and will be ignored.                                    | 10                |
| **backlog**            | The maximum length of the pending connections queue.                                             | 30                |
| **maxClients**         | The maximum number of concurrent client connections.                                             | 100               |
| **logger**             | `ILogger` instance used to log messages.                                                         | -                 |
| **maximumMessageSize** | **[optional]** Maximum size of received packets.                                                 | 1048576 (default) |

### Start listening for clients

After initializing the master the listening must be started using the start method.

``` csharp
master.Start([localEndpoint]);
```

| Parameter         | Description                                                                | Sample value              |
|-------------------|----------------------------------------------------------------------------|---------------------------|
| **localEndpoint** | **[optional]** The local IP address used to listen for client connections. | `IPAddress.Any` (default) |

### Stop listening for clients

To stop listening for new connections and to abort all client connection the stop method can be used.

``` csharp
master.Stop();
```

### Sample program

Example of using the master from `samples/SimpleServer` sample.

``` csharp
using LibUA.Server;
using Microsoft.Extensions.Logging;

namespace SimpleServer
{
    internal class Program
    {
        static ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

        static void Main(string[] args)
        {
            var app = new SimpleServerApplication();
            var server = new Master(app, 4840, 10, 30, 100, loggerFactory.CreateLogger<Master>());

            server.Start();
            Console.ReadKey();
            server.Stop();
        }
    }
}
```

## Application

By deriving your own class from Application class you can define the the information about the Server and its endpoints see the minimal requirements. In addition you can define how the server behaves by overwriting the methods of the Application.

### Minimal requirement

To be able to start the master using your application class you need to provide some basic information.

#### Provide a certificate and a private key

For OPC UA it is mandatory to authenticate the server using a certificate. You need to override the getters of the properties `ApplicationCertificate` and `ApplicationPrivateKey` to provide it.

Visit the the official documentation to learn more about the [Application Instance Certificate](https://reference.opcfoundation.org/Core/Part4/v104/docs/6.1.2).

The Simple Server sample generates an self-signed certificate, but for a productive environment you should use a certificate issued by an CA and stored in a certificate store.

#### Provide the application description

The application description required to provide clients information about the server. It becomes also part of the endpoint descriptions send to discovering clients.

``` csharp
public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
{
    ...
}
```

| Parameter           | Description                                                               |
|---------------------|---------------------------------------------------------------------------|
| **endpointUrlHint** | The network address that the Client used to access the DiscoveryEndpoint. |

To initialize an application descriptions you require to provide some information to the constructor.

``` csharp
var description = new ApplicationDescription(
    applicationUri,
    productUri,
    applicationName,
    type,
    gatewayServerUri,
    discoveryProfileUri,
    discoveryUrls);
```

| Parameter               | Description                                                                                                                                            | Sample value                                       |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| **applicationUri**      | The globally unique identifier for the application instance. This URI is used as ServerUri in Services if the application is a Server.                 | "urn:LibUA:Sample:SimpleServer"                    |
| **productUri**          | The globally unique identifier for the product.                                                                                                        | "http://quantensystems.com/"                       |
| **applicationName**     | A localized descriptive name for the application.                                                                                                      | new LocalizedText("en-US", "Simple Server sample") |
| **type**                | The type of application.                                                                                                                               | ApplicationType.Server                             |
| **gatewayServerUri**    | A URI that identifies the Gateway Server associated with the discoveryUrls. This value is not specified if the Server can be accessed directly.        | null                                               |
| **discoveryProfileUri** | A URI that identifies the discovery profile supported by the URLs provided. This value is not required, because LibUA supports the Discovery Services. | null                                               |
| **discoveryUrls**       | A list of URLs for the DiscoveryEndpoints provided by the application.                                                                                 | new string [] { "opc.tcp://localhost:4840" }       |

#### Provide the endpoint descriptions

To establish a secure channel the client and server require to negotiate the used security parameters. Therefor the server must provide a list of accepted endpoint settings.

``` csharp
public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
{
    ...
}
```

| Parameter           | Description                                                               |
|---------------------|---------------------------------------------------------------------------|
| **endpointUrlHint** | The network address that the Client used to access the DiscoveryEndpoint. |

The Server can support multiple endpoint settings and the client should use the best supported one. You can describe the supported endpoint settings using instances of the `EndpointDescription` class.

``` csharp
var endpoint = EndpointDescription(
    EndpointUrl,
    Server,
    ServerCertificate,
    SecurityMode,
    SecurityPolicyUri,
    UserIdentityTokens,
    TransportProfileUri,
    SecurityLevel);
```

| Parameter               | Description                                                                                                                                                                                                                                                                                         | Sample value                                          |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| **EndpointUrl**         | The URL for the Endpoint described. Use `endpointUrlHint` parameter to describe same endpoint as client uses to discover available endpoints.                                                                                                                                                       | "opc.tcp://localhost:4840"                            |
| **Server**              | The application description for the Server that the Endpoint belongs to.                                                                                                                                                                                                                            | GetApplicationDescription("opc.tcp://localhost:4840") |
| **ServerCertificate**   | The Application Instance Certificate issued to the Server.                                                                                                                                                                                                                                          | ApplicationCertificate.Export(X509ContentType.Cert)   |
| **SecurityMode**        | The type of security to apply to the messages.                                                                                                                                                                                                                                                      | MessageSecurityMode.None                              |
| **SecurityPolicyUri**   | The URI for SecurityPolicy to use when securing messages. Use the `Types`.`SLSecurityPolicyUris` array and the `SecurityPolicy` enum as index to obtain the URI.                                                                                                                                    | Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]  |
| **UserIdentityTokens**  | The user identity tokens that the Server will accept. The Client shall pass one of the UserIdentityTokens in the ActivateSession request.                                                                                                                                                           |                                                       |
| **TransportProfileUri** | The URI of the Transport Profile supported by the Endpoint.                                                                                                                                                                                                                                         | Types.TransportProfileBinary                          |
| **SecurityLevel**       | A numeric value that indicates how secure the EndpointDescription is compared to other EndpointDescriptions for the same Server. A value of 0 indicates that the EndpointDescription is not recommended and is only supported for backward compatibility. A higher value indicates better security. | 0                                                     |

### Address Space Table

If your server application implements the minimum requirements, you should be able to connect to an OPC UA client application. The nodes that contain the standard OPC UA data types and those specified by the OPC UA specification are already created and initialized.

You can add own nodes by adding your new instances of the `NodeObject` and `NodeVariable` to the `AddressSpaceTable` collection of your application instance.

#### Add folders

Folders are defined as objects that can organize other objects or variables.

``` csharp
NodeObject rootNode = new NodeObject(Id, BrowseName, DisplayName, Description, WriteMask, UserWriteMask, EventNotifier);
```

| Parameter         | Description                                                        | Sample value                              |
|-------------------|--------------------------------------------------------------------|-------------------------------------------|
| **Id**            | Unique node id of the node.                                        | new NodeId(2, 0)                          |
| **BrowseName**    | Qualified name used to browse the tree of nodes.                   | new QualifiedName("SampleRoot")           |
| **DisplayName**   | Display name of the node.                                          | new LocalizedText("Sample root")          |
| **Description**   | Description of the node.                                           | new LocalizedText("Sample root element.") |
| **WriteMask**     | Describes which attributes of the node are writeable.              | (int)AttributeWriteMask.None              |
| **UserWriteMask** | Describes which attributes of the node are writeable for the user. | (int)AttributeWriteMask.None              |
| **EventNotifier** |                                                                    | 0                                         |

To place our object in the browsable tree it is necessary to add two organization references. To the parent node we add a organize reference to our node and additional on our node a inverse organize reference to the parent. To add a root element for our nodes we can add the reference to the objects folder.

``` csharp
var objectsFolderId = new NodeId(UAConst.ObjectsFolder);

AddressSpaceTable[objectsFolderId]
    .References
    .Add(new ReferenceNode(new NodeId(UAConst.Organizes), rootNode.Id, false));

rootNode
    .References
    .Add(new ReferenceNode(new NodeId(UAConst.Organizes), objectsFolderId, true));
```

Add the node to the address space table to find the node by its node id and to ensure the node id is unique.

``` csharp
AddressSpaceTable.TryAdd(rootNode.Id, rootNode);
```

#### Add variables

Nodes having a value are created as variables.

``` csharp
NodeVariable randomNumber = new NodeVariable(id, browseName, displayName, description, writeMask, userWriteMask, accessLevel, userAccessLevel, minimumResamplingInterval, isHistorizing, dataType, defaultRank);
```

| Parameter                 | Description                                                        | Sample value                       |
|---------------------------|--------------------------------------------------------------------|------------------------------------|
| id                        | Unique node id of the node.                                        | new NodeId(2, 1)                   |
| browseName                | Qualified name used to browse the tree of nodes.                   | new QualifiedName("RandomSample")  |
| displayName               | Display name of the node.                                          | new LocalizedText("Random number") |
| description               | Description of the node.                                           | new LocalizedText("Random number") |
| writeMask                 | Describes which attributes of the node are writeable.              | (int)AttributeWriteMask.None       |
| userWriteMask             | Describes which attributes of the node are writeable for the user. | (int)AttributeWriteMask.None       |
| accessLevel               | Describes the level of access to the value.                        | AccessLevel.CurrentRead            |
| userAccessLevel           | Describes the level of access to the value the user has.           | AccessLevel.CurrentRead            |
| minimumResamplingInterval | Lowest accepted sampling rate                                      | 100.0                              |
| isHistorizing             | Defines the value of the IsHistorizing attribute.                  | false                              |
| dataType                  | Node id of the data type.                                          | new NodeId(UAConst.Double)         |
| defaultRank               |                                                                    | ValueRank.Scalar                   |

We need to add the references from and to the parent item organizing the variable node.

``` csharp
rootNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), randomNumber.Id, false));
randomNumber.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), rootNode.Id, true));

AddressSpaceTable.TryAdd(randomNumber.Id, randomNumber);
```
