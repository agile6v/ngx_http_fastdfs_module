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
=================

* [fastdfs_pass](#fastdfs_pass)
* [fastdfs_tracker_fetch](#fastdfs_tracker_fetch)
* [fastdfs_fileID](#fastdfs_fileID)
* [fastdfs_append_flag](#fastdfs_append_flag)
* [fastdfs_store_path_index](#fastdfs_store_path_index)
* [fastdfs_bind](#fastdfs_bind)
* [fastdfs_cmd](#fastdfs_cmd)
* [fastdfs_connect_timeout](#fastdfs_connect_timeout)
* [fastdfs_buffer_size](#fastdfs_buffer_size)
* [fastdfs_send_timeout](#fastdfs_send_timeout)
* [fastdfs_read_timeout](#fastdfs_read_timeout)
* [fastdfs_next_upstream](#fastdfs_next_upstream)
* [fastdfs_next_upstream_tries](#fastdfs_next_upstream_tries)
* [fastdfs_next_upstream_timeout](#fastdfs_next_upstream_timeout)
* [fastdfs_limit_rate](#fastdfs_limit_rate)


fastdfs_pass
-------------------
**syntax:** *fastdfs_pass 127.0.0.1:23000*

**default:** *--*

**context:** *location, if in location*

Sets the address of a FastDFS server. The address can be specified as a domain name or IP address, and an optional port:  
*	fastcgi_pass localhost:9000;

or as a UNIX-domain socket path:
*	fastcgi_pass unix:/tmp/fastcgi.socket;

If a domain name resolves to several addresses, all of them will be used in a round-robin fashion. In addition, an address can be specified as a server group.

[Back](#Directives)

fastdfs_tracker_fetch
-------------------
**syntax:** *fastdfs_tracker_fetch uri;*

**default:** *--*

**context:** *http, server, location*

This directive registers an access phase handler that will issue an Nginx subrequest to request the tracker server.

When the subrequest returns code is 200, then the control flow will continue to the later phase including the content phase configured by "fastdfs_pass".
For example,
```nginx
        location /download {
            fastdfs_cmd "download";
            fastdfs_tracker_fetch /fetch_tracker_srv;
            fastdfs_pass $storage_ip;
        }
        
        location /fetch_tracker_srv {
            internal;
            fastdfs_pass fdfs_tracker_servers;
        }
```

[Back](#Directives)

fastdfs_fileID
-------------------
**syntax:** *fastdfs_fileID  flag;*

**default:** *no*

**context:** *http, server, location*

This directive specifies the fileID keyword of the FastDFS.  The flag argument supports nginx variable. When performing the delete、append、download operations, fileID can't  be empty. For example,

nginx configuration is  as follow:
>	fastdfs_fileID $arg_fileID;

client request:
>  curl http://127.0.0.1/download?fileID=group1/M00/00/01/CgAL9FVA2buEBfn_AAAAAIYpzbw615.zip

[Back](#Directives)

fastdfs_append_flag
-------------------
**syntax:** *fastdfs_append_flag on;*

**default:** *off*

**context:** *http, server, location*

This directive is used to be enable append operation.  By default, file is not allowed to perform append operation. Must be enable this directive When file upload. 

[Back](#Directives)

fastdfs_store_path_index
-------------------
**syntax:** *fastdfs_store_path_index num;*

**default:** *-1*

**context:** *http, server, location*

This directive is used to be set the upload path. By default, file is uploaded to the storage path index according to tracker returned value. If this directive is set, it will cover the tracker returns value.

[Back](#Directives)

fastdfs_bind
-------------------
**syntax:** *fastdfs_bind*

**default:** *--*

**context:** *http, server, location*

Makes outgoing connections to a FastDFS server originate from the specified local IP address. Parameter value can contain variables (1.3.12). The special value off (1.3.12) cancels the effect of the fastcgi_bind directive inherited from the previous configuration level, which allows the system to auto-assign the local IP address.

[Back](#Directives)

fastdfs_cmd
-------------------
**syntax:** *fastdfs_cmd command;*

**default:** *--*

**context:** *http, server, location*

This directive specifies operation command. Commands include "upload、delete、download、append".

[Back](#Directives)

fastdfs_connect_timeout
-------------------
**syntax:** *fastdfs_connect_timeout time.*

**default:** *fastdfs_connect_timeout 60s.*

**context:** *http, server, location*

Defines a timeout for establishing a connection with a FastDFS server. It should be noted that this timeout cannot usually exceed 75 seconds. 

[Back](#Directives)

fastdfs_buffer_size
-------------------
**syntax:** *fastdfs_buffer_size size;*

**default:** *fastdfs_buffer_size 4k|8k;*

**context:** *http, server, location*

Sets the size of the buffer used for reading the first part of the response received from the FastDFS server. This part usually contains a small response header. This default size is the page size and not less than page size.

[Back](#Directives)

fastdfs_send_timeout
-------------------
**syntax:** *fastdfs_send_timeout time.*

**default:** *fastdfs_send_timeout 60s.*

**context:** *http, server, location*

Sets a timeout for transmitting a request to the FastDFS server. The timeout is set only between two successive write operations, not for the transmission of the whole request. If the FastDFS server does not receive anything within this time, the connection is closed.

[Back](#Directives)

fastdfs_read_timeout
-------------------
**syntax:** *fastdfs_read_timeout time.*

**default:** *fastdfs_read_timeout 60s.*

**context:** *http, server, location*

Defines a timeout for reading a response from the FastDFS server. The timeout is set only between two successive read operations, not for the transmission of the whole response. If the FastDFS server does not transmit anything within this time, the connection is closed.

[Back](#Directives)

fastdfs_next_upstream
-------------------
**syntax:** *fastdfs_next_upstream [ error | timeout | invalid_response | not_found | off ]*

**default:** *error timeout*

**context:** *http, server, location*

Specifies in which cases a request should be passed to the next server.

[Back](#Directives)

fastdfs_next_upstream_tries
-------------------
**syntax:** *fastdfs_next_upstream_tries number;*

**default:** *fastdfs_next_upstream_tries 0;*

**context:** *http, server, location*

> This directive can be used in nginx version 1.7.5 and above.

Limits the number of possible tries for passing a request to the next server. The 0 value turns off this limitation.

[Back](#Directives)

fastdfs_next_upstream_timeout
-------------------
**syntax:** *fastdfs_next_upstream_timeout time;*

**default:** *fastdfs_next_upstream_timeout 0;*

**context:** *http, server, location*

> This directive can be used in nginx version 1.7.5 and above.

Limits the time allowed to pass a request to the next server. The 0 value turns off this limitation.

[Back](#Directives)

fastdfs_limit_rate
-------------------
**syntax:** *fastdfs_limit_rate rate;*

**default:** *fastdfs_limit_rate 0;*

**context:** *http, server, location*

> This directive can be used in nginx version 1.7.7 and above.

Limits the speed of reading the response from the FastDFS server. The rate is specified in bytes per second. The zero value disables rate limiting. The limit is set per a request, and so if nginx simultaneously opens two connections to the FastDFS server, the overall rate will be twice as much as the specified limit. The limitation works only if buffering of responses from the FastDFS server is enabled.

[Back](#Directives)



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
            # Turn on this directive, to be able to perform the append opertaion.
            fastdfs_append_flag on;	
            fastdfs_tracker_fetch /fetch_tracker_srv;
            fastdfs_pass $storage_ip;
        }
        
        location /append {
            fastdfs_cmd "append";
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

