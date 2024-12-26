# DDoS Detector v2

### README outline
- [Module description](#module-description)
- [Input data](#input-data)
- [Input data (false positives)](#input-data-false-positives)
- [Output data](#output-data)
- [Module parameters](#module-parameters)

## Module description

This module processes incoming NetFlow records as a time series. This time series is aggregated in 5-second windows. From these five-second aggregates, the CUSUM statistic is then calculated.The CUSUM algorithm accumulates deviations from a calculated long-term average of network traffic (calculated with EWMA method). When these deviations exceed a predefined threshold, it triggers an alert, indicating a potential DDoS attack. Thresholds can be learned for the specific network using parameter -l.

To handle large volumes of data efficiently, the module utilizes the reversible Bin-Count sketch data structure. This allows it to compactly represent network traffic statistics without losing crucial details, enabling quick and memory-efficient storage and retrieval of data.

## Input data

| Item Name   | Data Type | Meaning                                                  |
|-------------|-----------|----------------------------------------------------------|
| DST_IP      | `ipaddr`  | Target IP address                                        |
| SRC_IP      | `ipaddr`  | Source IP address                                        |
| TIME_LAST   | `time`    | End time of the flow                                     |
| BYTES       | `uint64`  | Number of bytes transferred from `SRC_IP` to `DST_IP`    |
| PACKETS     | `uint32`  | Number of packets transferred from `SRC_IP` to `DST_IP`  |

## Input data (false positives)
Second input interface intended for reports which has been marked as false positive. It has got the same format as output interface, because user can easily edit it and send it back.


| Item Name            | Data Type | Meaning                                                                    |
|----------------------|-----------|----------------------------------------------------------------------------|
| DST_IP               | `ipaddr`  | Attack victim                                                              |
| TH_BYTES             | `double`  | Threshold for transferred bytes                                            |
| TH_PACKETS           | `double`  | Threshold for transferred packets                                          |
| TH_ENTROPY           | `double`  | Threshold for entropy                                                      |
| TH_RECV_SENT_BYTES   | `double`  | Threshold for the ratio between received and sent bytes                    |
| TH_RECV_SENT_FLOWS   | `double`  | Threshold for the ratio between incoming and outgoing flows                |
| SH_BYTES             | `double`  | Measured statistic of received bytes                                       |
| SH_PACKETS           | `double`  | Measured statistic of transferred packets                                  |
| SH_ENTROPY           | `double`  | Measured value of entropy of source IP addresses                           |
| SH_RECV_SENT_BYTES   | `double`  | Measured value of the ratio between sent and received bytes                |
| SH_RECV_SENT_FLOWS   | `double`  | Measured statistic of the ratio between outgoing and incoming flows        |
| CUSUM_ID             | `uint32`  | Identifier of the CUSUM detector that detected the attack                  |
| SRC_IPS              | `bytes`   | N source IP addresses that contributed the most to the attack              |

### Output data

| Item Name            | Data Type | Meaning                                                                    |
|----------------------|-----------|----------------------------------------------------------------------------|
| DST_IP               | `ipaddr`  | Attack victim                                                              |
| TH_BYTES             | `double`  | Threshold for transferred bytes                                            |
| TH_PACKETS           | `double`  | Threshold for transferred packets                                          |
| TH_ENTROPY           | `double`  | Threshold for entropy                                                      |
| TH_RECV_SENT_BYTES   | `double`  | Threshold for the ratio between received and sent bytes                    |
| TH_RECV_SENT_FLOWS   | `double`  | Threshold for the ratio between incoming and outgoing flows                |
| SH_BYTES             | `double`  | Measured statistic of received bytes                                       |
| SH_PACKETS           | `double`  | Measured statistic of transferred packets                                  |
| SH_ENTROPY           | `double`  | Measured value of entropy of source IP addresses                           |
| SH_RECV_SENT_BYTES   | `double`  | Measured value of the ratio between sent and received bytes                |
| SH_RECV_SENT_FLOWS   | `double`  | Measured statistic of the ratio between outgoing and incoming flows        |
| CUSUM_ID             | `uint32`  | Identifier of the CUSUM detector that detected the attack                  |
| SRC_IPS              | `bytes`   | N source IP addresses that contributed the most to the attack              |

**Module Parameters**
------------------
Bold indicates required. 
- **`m | mode`**: Defines the time mode in which the module is running. Requires a mandatory argument of `offline` for reading data from a file or `online` for listening on a live interface.
  
- **`f | subnetfile`**: Requires a mandatory argument specifying the path to a file containing protected subnets. Monitoring and detection will be performed for these subnets. The module expects one subnet per line in the format: `IP address/prefix sensitivity`. The prefix is optional if the user wants to specify only a specific IP address. Sensitivity should be a number from the interval `<0.1, 1>` and determines how sensitive the module should be to changes for the given subnet. A higher value means higher sensitivity and potentially more false positives. This part is optional, with a default value of `0.8`.

- `l | learning`: Defines the time duration for the module to learn the characteristics of the traffic before starting detection. It can be specified in seconds (s), minutes (m), hours (h), or days (d). For example, `0.5h = 30m = 1800s`. The module must always be started with this parameter first, which will create files with threshold values `thresholds.csv` and files with seeds for hash functions.

- `w | whitelist`: Similar to `subnetfile`, the specified file must be in the same format, but without sensitivity. Subnets listed in this file will be considered safe and will not appear in the reports. By default, the entire list of protected prefixes is assumed to be automatically in the list of safe prefixes.

- `q | quantile`: Specifies the quantile for selecting the threshold value after the learning period for prefixes that did not appear in the traffic during learning. The other threshold values are sorted, and a value corresponding to this quantile is chosen. By default, the `0.75` quantile is selected.

- `s | span`: The span of EWMA in CUSUM statistics. The alpha value is calculated from this using the formula `𝛼 = 2 / (span + 1)`. The default value is `60`, which means `𝛼 ≈ 0.03279`. During this time, no statistics are collected, so if learning is enabled then span should be many times smaller than the learning period.

- `d | dsketchwidth`: Specifies the number of columns in the sketch for target IP addresses. If the user does not specify this parameter, the value `1024` is used by default.

- `s | ssketchwidth`: Specifies the number of columns in the sketch for source IP addresses. If the user does not specify this parameter, the value `32,768` is used by default.

- `n | topn`: Defines how many source IP addresses should appear in the attack report. The module selects `n` source IP addresses that are not listed in the safe prefix list and have sent the most bytes to the target IP address. The default value is `5`.

- `t | interval`: Defines the interval after which a new report should be generated for a CUSUM algorithm. This prevents attacks from being reported in every window of the algorithm. It can be defined similarly to the learning interval.

Except these parameters, the module has also implicit *libtrap* parameters `-i IFC_SPEC`, `-h` and `-v` (see [Execute a module](https://github.com/CESNET/Nemea#try-out-nemea-modules)).