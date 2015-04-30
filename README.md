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
==========

* [fastdfs_pass](#fastdfs_pass)
* [fastdfs_tracker_fetch](#fastdfs_tracker_fetch)
* [fastdfs_fileID](#fastdfs_fileID)
* [fastdfs_append_flag](#fastdfs_append_flag)
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

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_tracker_fetch
-------------------
**syntax:** *fastdfs_tracker_fetch*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_fileID
-------------------
**syntax:** *fastdfs_fileID*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_append_flag
-------------------
**syntax:** *fastdfs_append_flag*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_bind
-------------------
**syntax:** *fastdfs_bind*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_cmd
-------------------
**syntax:** *fastdfs_cmd*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_connect_timeout
-------------------
**syntax:** *fastdfs_connect_timeout*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_buffer_size
-------------------
**syntax:** *fastdfs_buffer_size*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_send_timeout
-------------------
**syntax:** *fastdfs_send_timeout*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_read_timeout
-------------------
**syntax:** *fastdfs_read_timeout*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_next_upstream
-------------------
**syntax:** *fastdfs_next_upstream*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_next_upstream_tries
-------------------
**syntax:** *fastdfs_next_upstream_tries*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_next_upstream_timeout
-------------------
**syntax:** *fastdfs_next_upstream_timeout*

**default:** *no*

**context:** *http, server, location*

Reserved. 

[Back](#Directives)

fastdfs_limit_rate
-------------------
**syntax:** *fastdfs_limit_rate*

**default:** *no*

**context:** *http, server, location*

Reserved. 

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

