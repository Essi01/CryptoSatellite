# CryptoSatellite

**CryptoSatellite** is a bachelor's thesis project focused on evaluating symmetric encryption algorithms for secure satellite communication in resource-constrained environments.

The project investigates how encryption impacts performance on embedded platforms simulating satellite onboard computers. Algorithms such as AES, SPECK, ASCON, and ChaCha20 are tested across multiple embedded hardware platforms, including Portenta H7, Portenta X8, STM32H743ZIT6, and Verdin iMX8M Plus.

## Features

- Performance testing of symmetric encryption (latency, memory, energy usage)
- Hardware benchmarking in bare-metal and Linux environments
- Simulated communication between satellite and ground station
- Focus on real-world constraints in CubeSat-like systems

## Structure

- `portentaH7/`, `portentaX8/`, `stm32h743/`, `verdinimx8mplus/`: Platform-specific encryption tests
- `encryption-sim/`: Simulated data transmission environment
- `images/`, `data/`: Sample payloads and benchmarking data

## Purpose

This repository supports the thesis:  
**"Secure Communication in Resource-Constrained Systems: Evaluating Symmetric Encryption on Embedded Hardware"**  
University of Agder, 2025

## License

MIT License
