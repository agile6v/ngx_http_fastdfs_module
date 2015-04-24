
/*
 * Copyright (C) agile6v
 * Copyright (C) agile6v@agile6v.com
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


//  fastdfs process command
#define NGX_FDFS_UPLOAD_FILE                 1
#define NGX_FDFS_DOWNLOAD_FILE               2
#define NGX_FDFS_DELETE_FILE                 3
#define NGX_FDFS_QUERY_FILE_INFO             4

#define NGX_FDFS_TO_TRACKER                  1
#define NGX_FDFS_TO_STORAGE                  2

#define IP_ADDRESS_SIZE                      16
#define NGX_FDFS_PKG_LEN_SIZE                8
#define NGX_FDFS_GROUP_NAME_MAX_LEN          16

//  for storage
#define STORAGE_CMD_UPLOAD_FILE              11
#define STORAGE_CMD_DELETE_FILE              12
#define STORAGE_CMD_DOWNLOAD_FILE            14
#define STORAGE_CMD_QUERY_FILE_INFO          22


//  for tracker
#define TRACKER_CMD_RESPONSE                              100
#define TRACKER_CMD_SERVICE_QUERY_STORE_WITHOUT_GROUP_ONE 101
#define TRACKER_CMD_SERVICE_QUERY_FETCH_ONE               102
#define TRACKER_CMD_SERVICE_QUERY_UPDATE                  103


typedef struct {
    u_char pkg_len[NGX_FDFS_PKG_LEN_SIZE];
    u_char cmd;
    u_char status;
} ngx_http_fastdfs_proto_hdr;

typedef struct {
    u_char store_path_index;
    u_char upload_file_size[8];
    u_char ext_name[6];
} ngx_http_fdfs_upload_file_to_store;

typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_array_t               *fdfs_lengths;
    ngx_array_t               *fdfs_values;

    ngx_int_t                  index;
    ngx_uint_t                 gzip_flag;
    ngx_uint_t                 proto_cmd;       //  fdfs process command (upload、delete、download etc.)
    ngx_str_t                  uri;             //  location uri for tracker config
} ngx_http_fastdfs_loc_conf_t;

typedef struct {
    ngx_http_request_t        *request;
    ngx_http_request_t        *subrequest;
    ngx_str_t                  store_ip;
    ngx_uint_t                 proto_cmd;       //  process command  (upload、delete、download etc.)
    ngx_uint_t                 flag;            //  pass to tracker or storage
    ngx_uint_t                 done;
    ngx_uint_t                 status;
} ngx_http_fastdfs_ctx_t;

static void int2buff(int64_t n, u_char *buff);
static int64_t buff2int(const u_char *buff);
static ngx_int_t ngx_http_fastdfs_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_fastdfs_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastdfs_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastdfs_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastdfs_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastdfs_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastdfs_handle_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_fastdfs_filter_init(void *data);
static ngx_int_t ngx_http_fastdfs_filter(void *data, ssize_t bytes);
static ngx_int_t ngx_http_fastdfs_eval(ngx_http_request_t *r, 
    ngx_http_fastdfs_loc_conf_t *flcf);
static ngx_int_t ngx_http_fastdfs_storage_ip_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_fastdfs_access_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void ngx_http_fastdfs_abort_request(ngx_http_request_t *r);
static void ngx_http_fastdfs_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static void *ngx_http_fastdfs_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fastdfs_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_fastdfs_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fastdfs_tracker_fetch(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_conf_enum_t ngx_http_fastdfs_proto_cmd[] = {
    { ngx_string("upload"),     NGX_FDFS_UPLOAD_FILE },
    { ngx_string("download"),   NGX_FDFS_DOWNLOAD_FILE },
    { ngx_string("delete"),     NGX_FDFS_DELETE_FILE },
    { ngx_string("file_info"),  NGX_FDFS_QUERY_FILE_INFO },
    { ngx_string("monitor"),    NGX_FDFS_QUERY_FILE_INFO },
    { ngx_null_string,          0 }
};

static ngx_conf_bitmask_t  ngx_http_fastdfs_next_upstream_masks[] = {
    { ngx_string("error"),            NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"),          NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"),        NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"),              NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string,                0 }
};

static ngx_command_t  ngx_http_fastdfs_commands[] = {

    { ngx_string("fastdfs_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_fastdfs_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastdfs_tracker_fetch"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastdfs_tracker_fetch,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastdfs_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.local),
      NULL },
      
    { ngx_string("fastdfs_cmd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, proto_cmd),
      &ngx_http_fastdfs_proto_cmd },

    { ngx_string("fastdfs_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("fastdfs_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("fastdfs_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("fastdfs_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("fastdfs_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.next_upstream),
      &ngx_http_fastdfs_next_upstream_masks },

#if defined(nginx_version) && (nginx_version >= 1007005)
    { ngx_string("fastdfs_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("fastdfs_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.next_upstream_timeout),
      NULL },
#endif

    { ngx_string("fastdfs_gzip_flag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, gzip_flag),
      NULL },

#if defined(nginx_version) && (nginx_version >= 1007011)
    { ngx_string("fastdfs_limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastdfs_loc_conf_t, upstream.limit_rate),
      NULL },
#endif
      ngx_null_command
};

static ngx_str_t ngx_http_fastdfs_storag_ip_var = ngx_string("storage_ip");

static ngx_http_module_t  ngx_http_fastdfs_module_ctx = {
    ngx_http_fastdfs_add_variables,        /* preconfiguration */
    ngx_http_fastdfs_handle_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fastdfs_create_loc_conf,      /* create location configuration */
    ngx_http_fastdfs_merge_loc_conf        /* merge location configuration */
};

ngx_module_t  ngx_http_fastdfs_module = {
    NGX_MODULE_V1,
    &ngx_http_fastdfs_module_ctx,          /* module context */
    ngx_http_fastdfs_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_fastdfs_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_fastdfs_ctx_t         *ctx;
    ngx_http_fastdfs_loc_conf_t    *flcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastdfs_module);

    if (flcf->fdfs_lengths) {
        if (ngx_http_fastdfs_eval(r, flcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "fastdfs://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_fastdfs_module;

    u->conf = &flcf->upstream;

    u->create_request = ngx_http_fastdfs_create_request;
    u->reinit_request = ngx_http_fastdfs_reinit_request;
    u->process_header = ngx_http_fastdfs_process_header;
    u->abort_request = ngx_http_fastdfs_abort_request;
    u->finalize_request = ngx_http_fastdfs_finalize_request;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_fastdfs_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->request = r;
        ctx->subrequest = NULL;
        ctx->proto_cmd = flcf->proto_cmd;
        ctx->flag = NGX_FDFS_TO_TRACKER;

        ngx_http_set_ctx(r, ctx, ngx_http_fastdfs_module);
    }

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_fastdfs_filter_init;
    u->input_filter = ngx_http_fastdfs_filter;
    u->input_filter_ctx = ctx;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_fastdfs_create_request(ngx_http_request_t *r)
{
    size_t                               len;
    ngx_str_t                            fileID, group, filename;
    u_char                              *p;
    ngx_buf_t                           *b;
    ngx_http_upstream_t                 *u;
    ngx_http_fastdfs_ctx_t              *ctx;
    ngx_http_fastdfs_loc_conf_t         *flcf;
    ngx_chain_t                         *cl, *body;
    ngx_http_fastdfs_proto_hdr           fdfs_hdr;
    ngx_http_fdfs_upload_file_to_store   fdfs_upload_file_hdr;

    len = 0;
    u = r->upstream;
    ngx_memzero(&fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));
    ngx_memzero(&fdfs_upload_file_hdr, sizeof(ngx_http_fdfs_upload_file_to_store));

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fdfs create request : context is null.");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "fdfs create request : cmd=%ui, flag=%ui",
                    ctx->proto_cmd, ctx->flag);

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastdfs_module);
    
    switch (ctx->proto_cmd) {

        case NGX_FDFS_UPLOAD_FILE:
            
            if (ctx->flag == NGX_FDFS_TO_TRACKER) {
                len = sizeof(ngx_http_fastdfs_proto_hdr);
            } else {
                len = sizeof(ngx_http_fastdfs_proto_hdr) + sizeof(ngx_http_fdfs_upload_file_to_store);
            }

            break;

        case NGX_FDFS_DOWNLOAD_FILE:

            if ((ngx_http_arg(r, (u_char *) "fileID", 6, &fileID) != NGX_OK) || fileID.len <= 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "fdfs create request : fileID is emtpy.");
                return NGX_HTTP_NOT_ALLOWED;
            }

            p = (u_char *) ngx_strchr(fileID.data, '/');
            if (p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "fdfs create request : group not found. (%V)", &fileID);
                return NGX_HTTP_NOT_ALLOWED;
            }

            filename.len = fileID.data + fileID.len - (p + 1);
            filename.data = p + 1;

            group.len = p - fileID.data;
            group.data = ngx_pcalloc(r->pool, group.len + 1);
            if (group.data == NULL) {
                return NGX_ERROR;
            }

            p = ngx_copy(group.data, fileID.data, group.len);
            *p = '\0';

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "fdfs create request : download file %V, %V",
                            &group, &filename);

            if (ctx->flag == NGX_FDFS_TO_TRACKER) {
                len = sizeof(ngx_http_fastdfs_proto_hdr) + NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len;
            } else {
                /*
                 *  len = len(hdr) + file offset(8 byte) + download file size(8 byte)
                 *          + group name len(16 byte) + len(filename)
                 */
                len = sizeof(ngx_http_fastdfs_proto_hdr) + 8 + 8 + NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len;
            }

            break;

        case NGX_FDFS_DELETE_FILE:
            
            if ((ngx_http_arg(r, (u_char *) "fileID", 6, &fileID) != NGX_OK) || fileID.len <= 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "fdfs create request : fileID is emtpy.");
                return NGX_HTTP_NOT_ALLOWED;
            }

            p = (u_char *) ngx_strchr(fileID.data, '/');
            if (p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "fdfs create request : group not found. (%V)", &fileID);
                return NGX_HTTP_NOT_ALLOWED;
            }

            filename.len = fileID.data + fileID.len - (p + 1);
            filename.data = p + 1;

            group.len = p - fileID.data;
            group.data = ngx_pcalloc(r->pool, group.len + 1);
            if (group.data == NULL) {
                return NGX_ERROR;
            }

            p = ngx_copy(group.data, fileID.data, group.len);
            *p = '\0';

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "fdfs create request : download file %V, %V",
                            &group, &filename);

            if (ctx->flag == NGX_FDFS_TO_TRACKER) {
                len = sizeof(ngx_http_fastdfs_proto_hdr) + NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len;
            } else {
                len = sizeof(ngx_http_fastdfs_proto_hdr) + NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len;
            }

            break;
        default:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "fdfs create request : unknown process command (%ui).", ctx->proto_cmd);
            return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "fdfs create request : malloc=%z", len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    
    switch (ctx->proto_cmd) {

        case NGX_FDFS_UPLOAD_FILE:
            
            if (ctx->flag == NGX_FDFS_TO_TRACKER) {

                fdfs_hdr.cmd = TRACKER_CMD_SERVICE_QUERY_STORE_WITHOUT_GROUP_ONE;

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));

                u->request_bufs = cl;

            } else {

                fdfs_hdr.cmd = STORAGE_CMD_UPLOAD_FILE;
                int2buff(sizeof(ngx_http_fdfs_upload_file_to_store) + r->headers_in.content_length_n, fdfs_hdr.pkg_len);

                //  TODO:   add the directive of store_path_index
                fdfs_upload_file_hdr.store_path_index = 0;
                int2buff(r->headers_in.content_length_n, fdfs_upload_file_hdr.upload_file_size);
                ngx_memcpy(fdfs_upload_file_hdr.ext_name, "zip", 4);

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));
                b->last = ngx_copy(b->last, &fdfs_upload_file_hdr, sizeof(ngx_http_fdfs_upload_file_to_store));

                body = u->request_bufs;
                u->request_bufs = cl;

                while (body) {
                    b = ngx_alloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

                    cl->next = ngx_alloc_chain_link(r->pool);
                    if (cl->next == NULL) {
                        return NGX_ERROR;
                    }

                    cl = cl->next;
                    cl->buf = b;

                    body = body->next;
                }
            }

            break;

        case NGX_FDFS_DOWNLOAD_FILE:

            if (ctx->flag == NGX_FDFS_TO_TRACKER) {

                fdfs_hdr.cmd = TRACKER_CMD_SERVICE_QUERY_FETCH_ONE;
                int2buff(NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len, fdfs_hdr.pkg_len);

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));
                ngx_memcpy(b->last, group.data, group.len + 1);
                b->last += NGX_FDFS_GROUP_NAME_MAX_LEN;
                b->last = ngx_cpymem(b->last, filename.data, filename.len);

                u->request_bufs = cl;

            } else {

                fdfs_hdr.cmd = STORAGE_CMD_DOWNLOAD_FILE;

                int2buff(8 + 8 + NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len, fdfs_hdr.pkg_len);

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));
                int2buff(0, b->last); b->last += 8;   //  TODO
                int2buff(0, b->last); b->last += 8;
                ngx_memcpy(b->last, group.data, group.len + 1);
                b->last += NGX_FDFS_GROUP_NAME_MAX_LEN;
                b->last = ngx_copy(b->last, filename.data, filename.len);

                u->request_bufs = cl;
            }

            break;

        case NGX_FDFS_DELETE_FILE:
            
            if (ctx->flag == NGX_FDFS_TO_TRACKER) {

                fdfs_hdr.cmd = TRACKER_CMD_SERVICE_QUERY_UPDATE;
                int2buff(NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len, fdfs_hdr.pkg_len);

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));
                ngx_memcpy(b->last, group.data, group.len + 1);
                b->last += NGX_FDFS_GROUP_NAME_MAX_LEN;
                b->last = ngx_copy(b->last, filename.data, filename.len);

                u->request_bufs = cl;

            } else {
                fdfs_hdr.cmd = STORAGE_CMD_DELETE_FILE;
                int2buff(NGX_FDFS_GROUP_NAME_MAX_LEN + filename.len, fdfs_hdr.pkg_len);

                b->last = ngx_copy(b->last, &fdfs_hdr, sizeof(ngx_http_fastdfs_proto_hdr));

                ngx_memcpy(b->last, group.data, group.len + 1);
                b->last += NGX_FDFS_GROUP_NAME_MAX_LEN;
                b->last = ngx_copy(b->last, filename.data, filename.len);

                u->request_bufs = cl;
            }

            break;

        default:
            //  dummy
            break;
    }

    b->flush = 1;
    cl->next = NULL;
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_fastdfs_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_fastdfs_process_header(ngx_http_request_t *r)
{
    off_t                           pkg_len;
    ngx_uint_t                      status_n;
    ngx_http_upstream_t            *u;
    ngx_http_fastdfs_proto_hdr     *pfdfs_hdr;

    status_n = NGX_HTTP_OK;
    u = r->upstream;
    
    if (sizeof(ngx_http_fastdfs_proto_hdr) > (unsigned long) (u->buffer.last - u->buffer.pos)) {
        return NGX_AGAIN;
    }
    
    pfdfs_hdr = (ngx_http_fastdfs_proto_hdr *) u->buffer.pos;

    pkg_len = buff2int(u->buffer.pos);
    if (pkg_len < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fdfs sent invalid pkg length in response");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fdfs process hdr: %ui, %ui, %O", pfdfs_hdr->cmd, pfdfs_hdr->status, pkg_len);

    if (pfdfs_hdr->status != 0) {

        if (pfdfs_hdr->status == NGX_ENOENT) {
            status_n = NGX_HTTP_NOT_FOUND;
            goto done;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fdfs sent status is %d in response.", pfdfs_hdr->status);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

done:

    u->headers_in.content_length_n = pkg_len;
    u->headers_in.status_n = status_n;
    u->state->status = status_n;
    u->buffer.pos += sizeof(ngx_http_fastdfs_proto_hdr);
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_fastdfs_filter_init(void *data)
{
    ngx_http_fastdfs_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n;
    } else {
        u->length = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastdfs_filter(void *data, ssize_t bytes)
{
    ngx_http_fastdfs_ctx_t  *ctx = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NGX_OK;
}


static void
ngx_http_fastdfs_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http fastdfs request");
    return;
}


static void
ngx_http_fastdfs_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http fastdfs request");
    return;
}


static void *
ngx_http_fastdfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fastdfs_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastdfs_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

#if defined(nginx_version) && (nginx_version >= 1007005)
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
#endif

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

#if defined(nginx_version) && (nginx_version >= 1007011)
    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
#endif

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;


    conf->index = NGX_CONF_UNSET;
    conf->gzip_flag = NGX_CONF_UNSET_UINT;
    conf->proto_cmd = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_fastdfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fastdfs_loc_conf_t *prev = parent;
    ngx_http_fastdfs_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

#if defined(nginx_version) && (nginx_version >= 1007005)
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);
#endif

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

#if defined(nginx_version) && (nginx_version >= 1007011)
    ngx_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);
#endif

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NGX_CONF_UNSET) {
        conf->index = prev->index;
    }

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);
    ngx_conf_merge_uint_value(conf->proto_cmd, prev->proto_cmd, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_fastdfs_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastdfs_loc_conf_t *flcf = conf;

    ngx_str_t                 *value, *url;
    ngx_url_t                  u;
    ngx_uint_t                 n;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_script_compile_t  sc;

    if (flcf->upstream.upstream || flcf->fdfs_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_fastdfs_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &flcf->fdfs_lengths;
        sc.values = &flcf->fdfs_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (flcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_fastdfs_handle_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_fastdfs_access_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastdfs_access_handler(ngx_http_request_t *r)
{
    ngx_http_request_t                    *sr;
    ngx_http_post_subrequest_t            *ps;
    ngx_http_fastdfs_ctx_t                *ctx, *sub_ctx;
    ngx_http_fastdfs_loc_conf_t           *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastdfs_module);

    if (flcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fdfs access handler : %V", &flcf->uri);

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        /* return appropriate status */
        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fdfs request unexpected status: %d", ctx->status);

        return ctx->status;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_fastdfs_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_fastdfs_access_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &flcf->uri, &r->args, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //  create subrequest context
    sub_ctx = ngx_pcalloc(sr->pool, sizeof(ngx_http_fastdfs_ctx_t));
    if (sub_ctx == NULL) {
        return NGX_ERROR;
    }

    sub_ctx->subrequest = NULL;
    sub_ctx->request = sr;
    sub_ctx->flag = NGX_FDFS_TO_TRACKER;
    sub_ctx->proto_cmd = flcf->proto_cmd;

    ngx_http_set_ctx(sr, sub_ctx, ngx_http_fastdfs_module);

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;
    ctx->request = r;
    ctx->flag = NGX_FDFS_TO_STORAGE;
    ctx->proto_cmd = flcf->proto_cmd;

    ngx_http_set_ctx(r, ctx, ngx_http_fastdfs_module);

    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_fastdfs_access_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_fastdfs_ctx_t      *ctx = data;
    ngx_str_t                    value;
    ngx_int_t                    port;
    u_char                       /*store_path_index*/*p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fdf access request done s:%d", r->headers_out.status);
                   
    ctx->done = 1;
    ctx->status = r->headers_out.status;
                   
    if (r->headers_out.status != NGX_HTTP_OK) {
        return rc;
    }
    
    value.len = r->upstream->out_bufs->buf->last - r->upstream->out_bufs->buf->pos;
    value.data = r->upstream->out_bufs->buf->pos;
   
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fdfs request response :%V", &value);

    switch (ctx->proto_cmd) {

        case NGX_FDFS_UPLOAD_FILE:
        case NGX_FDFS_DOWNLOAD_FILE:
        case NGX_FDFS_DELETE_FILE:

            ctx->store_ip.data = ngx_pcalloc(r->pool, IP_ADDRESS_SIZE + 1 + 8);
            if (ctx->store_ip.data == NULL) {
                return NGX_ERROR;
            }

            port = buff2int(r->upstream->out_bufs->buf->pos + \
                             NGX_FDFS_GROUP_NAME_MAX_LEN + IP_ADDRESS_SIZE - 1);

            p = ngx_sprintf(ctx->store_ip.data, "%s:%d", r->upstream->out_bufs->buf->pos + \
                                            NGX_FDFS_GROUP_NAME_MAX_LEN, port);

            ctx->store_ip.len = p - ctx->store_ip.data;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fdfs access done: %V", &ctx->store_ip);
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "fdfs access done : proto cmd is unkonwn (%ui).", ctx->proto_cmd);
            break;
    }

    return rc;
}


static char *
ngx_http_fastdfs_tracker_fetch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastdfs_loc_conf_t *flcf = conf;

    ngx_str_t        *value;

    if (flcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->uri.len = 0;
        flcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    flcf->uri = value[1];

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_fastdfs_storage_ip_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_fastdfs_ctx_t              *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fastdfs_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fastdfs get context is null.");
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->store_ip.len <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fastdfs get ip of storage is null.");
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->store_ip.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->store_ip.data;

    return NGX_OK;
}

static ngx_int_t 
ngx_http_fastdfs_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t             *var;

    var = ngx_http_add_variable(cf, &ngx_http_fastdfs_storag_ip_var, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_fastdfs_storage_ip_variable;
        
    return NGX_OK;
}

static ngx_int_t
ngx_http_fastdfs_eval(ngx_http_request_t *r, ngx_http_fastdfs_loc_conf_t *flcf)
{
    ngx_url_t             url;
    ngx_http_upstream_t  *u;

    ngx_memzero(&url, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &url.url, flcf->fdfs_lengths->elts, 0,
                            flcf->fdfs_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
         if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = r->upstream;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs && url.addrs[0].sockaddr) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->naddrs = 1;
        u->resolved->host = url.addrs[0].name;

    } else {
        u->resolved->host = url.host;
        u->resolved->port = url.port;
        u->resolved->no_port = url.no_port;
    }

    return NGX_OK;
}


static void 
int2buff(int64_t n, u_char *buff)
{
    u_char *p;
    p = (u_char *) buff;
    *p++ = (n >> 56) & 0xFF;
    *p++ = (n >> 48) & 0xFF;
    *p++ = (n >> 40) & 0xFF;
    *p++ = (n >> 32) & 0xFF;
    *p++ = (n >> 24) & 0xFF;
    *p++ = (n >> 16) & 0xFF;
    *p++ = (n >> 8) & 0xFF;
    *p++ = n & 0xFF;
}

static int64_t 
buff2int(const u_char *buff)
{
    u_char *p;
    p = (u_char *) buff;
    return (((int64_t)(*p)) << 56) | \
        (((int64_t)(*(p+1))) << 48) |  \
        (((int64_t)(*(p+2))) << 40) |  \
        (((int64_t)(*(p+3))) << 32) |  \
        (((int64_t)(*(p+4))) << 24) |  \
        (((int64_t)(*(p+5))) << 16) |  \
        (((int64_t)(*(p+6))) << 8) | \
        ((int64_t)(*(p+7)));
}
