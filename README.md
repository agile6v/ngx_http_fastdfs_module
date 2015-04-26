About
====
The **ngx_http_fastdfs_module** allows passing requests to a FastDFS server.

Note: Different from the [fastdfs-nginx-module][], this module supports many features such as upload、download、delete etc. The [fastdfs-nginx-module][] only supports download files from local disk.

*This module is not distributed with the Nginx source.*  See [the installation instructions](#installation).

Installation
====
`./configure --add-module=/path/to/ngx_http_fastdfs_module`   


Directives
====


Sample Configuration
====



See also
========
* [FastDFS][]

[FastDFS]: https://github.com/happyfish100/fastdfs
[fastdfs-nginx-module]: https://github.com/happyfish100/fastdfs-nginx-module

