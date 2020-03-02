# f-pacs
An architecture to secure medical imaging in federated storage

## Abstract
Sharing medical imaging has always been cumbersome. Acquisition locations are isolated from care centers, and data sharing is kept to a minimum due to legal concerns. By leveraging current distributed technologies, we propose a federation of data curators to construct a distributed PACS service. Data backups in encrypted format can freely circulate between data curators, resulting in high availability and redundancy. Our proposal is focused on the management of symmetric encryption keys such that no single data curator is able to attack and recover those keys. A $(t,n)$-threshold scheme is used to recover those keys. The scheme supports break-the-glass requirements and data-subject's ownership. We prove the correctness and security of the scheme and present measurements of scalability.

## Dependencies
* rustc 1.41
* cargo 1.41

## Build
Build with release for optimal results.

```
cargo build --release
```

## Usage
This project is a tool to measure running times of the proposed P-ID scheme. The tool accepts parameters to setup the number of parties (n) and the threshold value (t).

```
Statistics for Rn/Fn 1.0
Micael Pedrosa <micaelpedrosa@ua.pt>
Performs time measurements for Rn/Fn (create/recover)

USAGE:
    f-pacs [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    Fn      Selects the Fn test
    Rn      Selects the Rn test
    help    Prints this message or the help of the given subcommand(s)
```

with the result output:

```
--Rn test--
Rn-Setup: (t: <threshold>, n: <2*t + 1>, size: <Rn chain size>)
Rn-Test - (create: <time for chain creation>, recover: <time for chain recovering>, alpha: <time to recover the multiparty computation of alpha>)
```

and

```
Fn-Setup: (size: <file size>)
Fn-Test - (encrypt: <encryption throughput>, dencrypt: <decryption throughput>)
```