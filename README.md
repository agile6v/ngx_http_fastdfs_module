About
====
The **ngx_http_fastdfs_module** allows passing requests to a FastDFS server.

Note: This module supports many features such as upload、download、delete etc. The [fastdfs-nginx-module][] only supports download files from local disk.


![flowchart][flowchart]


*This module is not distributed with the Nginx source.*  See [the installation instructions](#installation).

Installation
====
`./configure --add-module=/path/to/ngx_http_fastdfs_module`   


Directives
====


Sample Configuration
====
```nginx
	upstream fdfs_tracker_servers {
        server 129.168.1.100:22124;
    }
	
	http {
	    listen       80;
        server_name  localhost;
        client_max_body_size 100m;
        fastdfs_fileID "$arg_fileID";

        location /upload {
            fastdfs_cmd "upload";
            fastdfs_tracker_fetch /fetch_tracker_srv;
            fastdfs_pass $storage_ip;
        }

        location /download {
            fastdfs_cmd "download";
            fastdfs_tracker_fetch /fetch_tracker_srv;
            fastdfs_pass $storage_ip;
        }

        location /delete {
            fastdfs_cmd "delete";
            fastdfs_tracker_fetch /fetch_tracker_srv;
            fastdfs_pass $storage_ip;
        }
        location /fetch_tracker_srv {
            internal;
            fastdfs_pass fdfs_tracker_servers;
        }
	}

```


See also
========
* [FastDFS][]

[FastDFS]: https://github.com/happyfish100/fastdfs
[fastdfs-nginx-module]: https://github.com/happyfish100/fastdfs-nginx-module
[flowchart]: https://github.com/agile6v/ngx_http_fastdfs_module/blob/master/ngx_http_fastdfs.png

