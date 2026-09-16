# go-upf
### The specific version
**Note:** Please make sure to check your UPF version and use a compatible gtp5g version according to the table below.

|free5GC Version| UPF Version | Compatible gtp5g Versions |
|-----------------|-----------------|--------------------------|
|v4.2.2| v1.2.10 | >= 0.9.3 and < 0.10.3 |
|v4.2.1| v1.2.9 | >= 0.9.3 and < 0.10.3 |
|v4.2.0| v1.2.8 | >= 0.9.3 and < 0.10.3 |
|v4.1.0| v1.2.7 | >= 0.9.3 and < 0.10.3 |
|v4.0.1| v1.2.6 | >= 0.9.3 and < 0.10.3 |
|v4.0.0| v1.2.6 | >= 0.9.3 and < 0.10.3 |
|v3.4.5| v1.2.5 | >= 0.9.3 and < 0.10.3 |
|v3.4.4| v1.2.4 | >= 0.9.3 and < 0.10.3 |
|v3.4.3| v1.2.3 | >= 0.8.6 and < 0.9.0 |
|v3.4.2| v1.2.3 | >= 0.8.6 and < 0.9.0 |
|v3.4.1| v1.2.2 | >= 0.8.6 and < 0.9.0 |
|v3.4.0| v1.2.1 | >= 0.8.6 and < 0.9.0 |
|v3.3.0| v1.2.0 | >= 0.8.1 and < 0.9.0 |
|v3.2.1| v1.1.0 | >= 0.7.0 and < 0.7.0 |
|v3.2.0| v1.1.0 | >= 0.7.0 and < 0.7.0 |

### QoS PFCP integration

See [PFCP integration and logging](docs/qos_pfcp.md) for automatic QoS policy synchronization.

The lab configuration is [config/upfcfg.yaml](config/upfcfg.yaml), also used by
the default config path. It maps N3/DL to `enp0s8` and N6/UL to `enp0s9`.
Adjust the addresses and interfaces for your deployment before starting UPF.
FlowQoS binding requires the companion gtp5g ABI/update changes described in
[binding integration](docs/qos_binding.md); TC/BPF enforcement is not yet implemented.
