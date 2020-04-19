# LibUA
Open-source OPC UA client and server library for .NET and .NET Core based on IEC 62541. Available as source files, a demo client and a demo server. Tested and commercially used in industrial applications with commercial vendors' UA servers and clients.

### Features
- Fully supported OPC UA core client and OPC UA server specification.
- OPC UA binary protocol with chunking.
- Optimized memory buffers for encoding/decoding large and complex structures to/from raw bytes.
- Support for all message types, node types, and default address space from the UA specification.
- Support for signing and encrypted security profiles.
- Anonymous, user/pass and certificate-based authentication.
- Sessions, subscriptions (data change notifications and custom notifications), custom events and alarming.
- Extendable server address space with hooks for client requests for access control, read handlers, write handlers, etc.
- Support for reads, writes, updates, historical data and aggregation.
- Server instances have low overhead: tested with hundreds of clients performing simultaneous historical reads, data change notification subscriptions and real-time writes.

### Platforms
.NET 4.5 or .NET Standard 2.0

### License
Free for commercial use under the Apache License 2.0. Please give credit if you find this source useful.
