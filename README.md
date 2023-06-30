# PW.LibUA
Open-source OPC UA client and server library for .NET (deprecated) and .NET Core based on IEC 62541. Available as source files, a demo client and a demo server. Tested and commercially used in industrial applications with commercial vendors' UA servers and clients.

Available as a nuget package for .NET Core (1.0.8):
https://www.nuget.org/packages/nauful-LibUA-core

Forked from https://github.com/nauful/LibUA.

### Features
- Fully supported OPC UA core client and OPC UA server specification.
- OPC UA binary protocol with chunking.
- Security profiles None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep (.NET Standard only) and Aes256Sha256RsaPss (.NET Standard only).
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
- .NET 4.8 is deprecated and not actively maintained.

### License
Free for commercial use under the Apache License 2.0. Please give credit if you find this source useful.

### Errata
The demo client and server applications can create self-signed certificates with sufficient fields for most usage. Remember to move these to the trusted directory on a server when connecting to a server for the first time.
