# LibUA
Open-source OPC UA client and server library for .NET (deprecated) and .NET Core based on IEC 62541. Available as source files, a demo client and a demo server. Tested and commercially used in industrial applications with commercial vendors' UA servers and clients.

Available as a nuget package for .NET Core (1.0.3):
https://www.nuget.org/packages/nauful-LibUA

### Features
- Fully supported OPC UA core client and OPC UA server specification.
- OPC UA binary protocol with chunking.
- Security profiles None, Basic128Rsa15, Basic256 and Basic256Sha256.
- Optimized memory buffers for encoding/decoding large and complex structures to/from raw bytes.
- Support for all message types, node types, and default address space from the UA specification.
- Support for signing and encrypted security profiles.
- Anonymous, user/pass and certificate-based authentication.
- Sessions, subscriptions (data change notifications and custom notifications), custom events and alarming.
- Extendable server address space with hooks for client requests for access control, read handlers, write handlers, etc.
- Support for reads, writes, updates, historical data and aggregation.
- Server instances have low overhead: tested with hundreds of clients performing simultaneous historical reads, data change notification subscriptions and real-time writes.

### Platforms
- .NET Standard 2.0
- .NET 4.8 is deprecated and not actively mantained.

### License
Free for commercial use under the Apache License 2.0. Please give credit if you find this source useful.

### Errata
Here's a more complete certificate if the default certificate created by the demo client/server is insufficient: https://github.com/nauful/LibUA/files/4586442/lubua-clntsrvcert.zip
