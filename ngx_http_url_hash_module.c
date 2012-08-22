#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_pool_t      *pool;
    ngx_array_t     *backends;
} ngx_http_url_hash_conf_ctx_t;

typedef struct {
    ngx_array_t     *backends;
} ngx_http_url_hash_ctx_t;

static void *ngx_http_url_hash_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_url_hash_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static char *ngx_http_url_hash_block(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static ngx_command_t ngx_http_url_hash_commands[] = {
    {
        ngx_string("url_hash"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
            | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
        ngx_http_url_hash_block,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_url_hash_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

ngx_module_t ngx_http_url_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_url_hash_module_ctx,
    ngx_http_url_hash_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_url_hash(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf) {
    ngx_str_t                       *value;
    ngx_str_t                       *c;
    ngx_http_url_hash_conf_ctx_t    *ctx;
    ctx = cf->ctx;

    value = cf->args->elts;
    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid number of backend parameters");
        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[0].data, "backend", 7) == 0) {
        if (ctx->backends == NULL) {
            ctx->backends = ngx_array_create(ctx->pool, 4, 
                    sizeof(ngx_str_t));
            if (ctx->backends == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "Out of memory");
                return NGX_CONF_ERROR;
            }
        }

        c = ngx_array_push(ctx->backends);
        if (c == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "Out of memory");
            return NGX_CONF_ERROR;
        }
        c->data = ngx_pstrdup(ctx->pool, &value[1]);
        if (c->data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "Out of memory");
            return NGX_CONF_ERROR;
        }
        c->len = value[1].len;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid url hash parameters");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_uint_t ngx_http_request_hash_index(ngx_http_request_t *r, 
        ngx_http_url_hash_ctx_t *ctx) {
    return ngx_crc32_short(r->uri.data, r->uri.len) % ctx->backends->nelts;
}

static ngx_int_t ngx_http_url_hash_variable(ngx_http_request_t *r, 
        ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_url_hash_ctx_t *urlhash = (ngx_http_url_hash_ctx_t *)data;
    ngx_uint_t  nelts;
    size_t      len;
    size_t      offset = 0;
    size_t      http_len = sizeof("http://") - 1;
    size_t      host_len;
    ngx_uint_t  index = 0;
    u_char      *location;
    u_char      *failed_location = "http://127.0.0.1/";

    nelts = urlhash->backends->nelts;
    index = ngx_http_request_hash_index(r, urlhash);
    host_len = ((ngx_str_t *)urlhash->backends->elts + index)->len;
    len = http_len + host_len + r->uri.len;
    location = ngx_pcalloc(r->pool, len + 1);
    if (location == NULL) {
        goto error;
    }

    ngx_memzero(location, len + 1);

    ngx_memcpy(location, "http://", http_len);
    offset += http_len;
    ngx_memcpy(location + offset, 
        ((ngx_str_t *)urlhash->backends->elts + index)->data,
        host_len);
    offset += host_len;
    if (location[offset - 1] == '/') {
        --offset; /* uri partion has a '/', so eliminate it. */
    }
    ngx_memcpy(location + offset, r->uri.data, r->uri.len);
    offset += r->uri.len;

    v->len = offset;
    v->data = location;
    return NGX_OK;
error:
    v->len = strlen((char *)failed_location);
    v->data = failed_location;
    return NGX_OK;
}

static char *ngx_http_url_hash_block(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf) {
    char                            *rv;
    ngx_str_t                       *value, name;
    ngx_http_url_hash_ctx_t         *uh;
    ngx_http_url_hash_conf_ctx_t    ctx;
    ngx_http_variable_t             *var;
    ngx_conf_t                      save;
    ngx_pool_t                      *pool;

    value = cf->args->elts;

    uh = ngx_palloc(cf->pool, sizeof(ngx_http_url_hash_ctx_t));
    if (uh == NULL) {
        return NGX_CONF_ERROR;
    }

    /* eliminate '$' character */
    name = value[1];
    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_url_hash_variable;
    var->data = (uintptr_t)uh;

    pool = ngx_create_pool(16384, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ctx, sizeof(ngx_http_url_hash_conf_ctx_t));
    ctx.pool = cf->pool;
    
    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = ngx_http_url_hash;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    uh->backends = ctx.backends;
    ngx_destroy_pool(pool);
    return rv;
}
