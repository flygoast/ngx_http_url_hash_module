#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <math.h>

#define DEFAULT_SLICE_SIZE      (1024 * 1024 * 10)   /* 10M */

#define STRATEGY_HASH        1   /* general hashing method */
#define STRATEGY_WHASH       2   /* weighed hashing */
#define STRATEGY_CHASH       3   /* consistent hashing */

typedef struct {
    uint32_t        point;      /* point on circle */
    ngx_uint_t      index;      /* server index in backends array */
} chash_vnode;

typedef struct {
    ngx_str_t       host;
    ngx_int_t       weight;
} server_info;

typedef struct {
    ngx_pool_t      *pool;
    ngx_array_t     *backends;
    ngx_uint_t      slice_size;
    ngx_int_t       strategy;
} ngx_http_url_hash_conf_ctx_t;

typedef struct {
    ngx_array_t     *backends;
    ngx_uint_t      slice_size;
    ngx_int_t       strategy;
    ngx_array_t     *whash_space;
    ngx_array_t     *chash_continuum;
} ngx_http_url_hash_ctx_t;

static void ngx_md5(u_char result[16], u_char *data) {
    ngx_md5_t md5;
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, ngx_strlen(data));
    ngx_md5_final(result, &md5);
}

typedef int(*vnodecmp_pt)(const void *, const void *);

static int ngx_http_url_hash_vnode_cmp(chash_vnode *a, chash_vnode *b) {
    return (a->point < b->point) ? -1 : ((a->point > b->point) ? 1 : 0);
}

static ngx_int_t ngx_http_url_hash_whash_init(
        ngx_http_url_hash_ctx_t *ctx, ngx_pool_t *pool) {
    ngx_uint_t      i, j;
    ngx_int_t       *weight;
    server_info     *si = ctx->backends->elts;
    ctx->whash_space = ngx_array_create(pool, 4, sizeof(ngx_int_t));
    if (ctx->whash_space == NULL) {
        return -1;
    }

    for (i = 0; i < ctx->backends->nelts; ++i) {
        weight = ngx_array_push_n(ctx->whash_space, si[i].weight);
        for (j = 0; j < si[i].weight; ++j) {
            weight[j] = i;
        }
    }
    return 0;
}

static ngx_uint_t ngx_http_url_hash_whash_find(ngx_http_url_hash_ctx_t *ctx,
        ngx_uint_t index) {
    ngx_int_t *idx = ctx->whash_space->elts;
    return idx[index % ctx->whash_space->nelts];
}

static ngx_int_t ngx_http_url_hash_chash_init(
        ngx_http_url_hash_ctx_t *ctx, ngx_pool_t *pool) {
    ngx_uint_t      i;
    ngx_int_t       total_weight = 0;
    server_info     *si = ctx->backends->elts;
    chash_vnode     *vnode;
    ctx->chash_continuum = ngx_array_create(pool, 4, 
            sizeof(chash_vnode));
    if (ctx->chash_continuum == NULL) {
        return -1;
    }

    /* calculate total weight */
    for (i = 0; i < ctx->backends->nelts; ++i) {
        total_weight += si[i].weight;
    }

    /* generate the consistent hash continuum */
    for (i = 0; i < ctx->backends->nelts; ++i) {
        float percent = (float)si[i].weight / (float)total_weight;
        unsigned int nvnode = floorf(percent * 40.0 * 
                (float)ctx->backends->nelts);
        int j = 0;
        for (j = 0; j < nvnode; ++j) {
            int k = 0;
            char temp_vnode[128];
            u_char result[16];
            ngx_snprintf(temp_vnode, 128, "%V-%d", &si[i].host, j);
            ngx_md5(result, temp_vnode);
            for (k = 0; k < 4; ++k) {
                vnode = ngx_array_push(ctx->chash_continuum);
                if (vnode == NULL) {
                    return -1;
                }
                vnode->point = (result[3 + k * 4] << 24)
                            |  (result[2 + k * 4] << 16)
                            |  (result[1 + k * 4] << 8)
                            |  (result[k * 4]);
                vnode->index = i;
            }
        }

        /* sort in ascending order of "point" */
        qsort((void *)ctx->chash_continuum, ctx->chash_continuum->nelts, 
            sizeof(vnode), 
            (vnodecmp_pt)ngx_http_url_hash_vnode_cmp);
    }
    return 0;
}

static ngx_uint_t ngx_http_url_hash_chash_find(ngx_http_url_hash_ctx_t *ctx,
        ngx_uint_t index) {
    uint32_t hash = index & 0xffffffff;
    ngx_int_t highp = ctx->chash_continuum->nelts;
    ngx_int_t lowp = 0, midp;
    ngx_uint_t midval, midval1;
    chash_vnode     *vnodes = ctx->chash_continuum->elts;

    /* divide and conquer array search to find server with next
     * biggest point after what this key hashes to */
    while (1) {
        midp = (ngx_int_t)((lowp + highp) / 2);
        if (midp == ctx->chash_continuum->nelts) {
            return vnodes[0].index; /* if at the end, roll back to zeroth */
        }

        midval = vnodes[midp].point;
        midval1 = (midp == 0 ? 0 : vnodes[midval - 1].point);
        if (hash <= midval && hash > midval1) {
            return vnodes[midp].index;
        }
        
        if (midval < hash) {
            lowp = midp + 1;
        } else {
            highp = midp - 1;
        }

        if (lowp > highp) {
            return vnodes[0].index;
        }
    }

    /* never get here */
    return vnodes[0].index;
}

static ngx_int_t ngx_http_url_hash_parse_strategy(u_char *strategy_str) {
    if (strcmp(strategy_str, "hash") == 0) {
        return STRATEGY_HASH;
    } else if (strcmp(strategy_str, "whash") == 0) {
        return STRATEGY_WHASH;
    } else if (strcmp(strategy_str, "chash") == 0) {
        return STRATEGY_CHASH;
    } else {
        return STRATEGY_HASH; /* default: hash */
    }
}

static ngx_int_t ngx_http_url_hash_range_parse(ngx_http_request_t *r, 
        ngx_int_t *len) {
    u_char            *p;
    ngx_int_t         start = 0;

    p = r->headers_in.range->value.data + 6;
    if (len) {
        *len = 0;
    }

    for ( ;; ) {
        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return -1;
            }

            while (*p >= '0' && *p <= '9') {
                start = start * 10 + *p++ - '0';
                if (len) {
                    ++*len;
                }
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return -1;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    return start;
}

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
    server_info                     *si;
    ngx_str_t                       *value;
    ngx_http_url_hash_conf_ctx_t    *ctx;
    ctx = cf->ctx;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "backend") == 0) {
        if (cf->args->nelts != 3) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid number of backend parameters");
            return NGX_CONF_ERROR;
        }

        if (ctx->backends == NULL) {
            ctx->backends = ngx_array_create(ctx->pool, 4, 
                    sizeof(server_info));
            if (ctx->backends == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "Out of memory");
                return NGX_CONF_ERROR;
            }
        }

        si = ngx_array_push(ctx->backends);
        if (si == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "Out of memory");
            return NGX_CONF_ERROR;
        }
        si->host.data = ngx_pstrdup(ctx->pool, &value[1]);
        if (si->host.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "Out of memory");
            return NGX_CONF_ERROR;
        }
        si->host.len = value[1].len;
        si->weight = ngx_atoi(value[2].data, value[2].len);
    } else if (ngx_strcmp(value[0].data, "slice_size") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid number of slice_size parameters");
            return NGX_CONF_ERROR;
        }

        ctx->slice_size = ngx_parse_size(&value[1]);
        if (ctx->slice_size == (size_t)NGX_ERROR
                || ctx->slice_size == 0) {
            ctx->slice_size = DEFAULT_SLICE_SIZE; /* default size 10K */
        }
    } else if (ngx_strcmp(value[0].data, "strategy") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid number of strategy parameters");
            return NGX_CONF_ERROR;
        }

        ctx->strategy = ngx_http_url_hash_parse_strategy(value[1].data);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid url_hash parameters");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_uint_t ngx_http_request_hash_index(ngx_http_request_t *r, 
        ngx_http_url_hash_ctx_t *ctx) {
    ngx_uint_t index = 0;
    ngx_int_t range_id = 0;
    ngx_int_t len = 0;
    u_char *url_range;
    int temp_len = 0;

    if (r->headers_in.range == NULL 
            || r->headers_in.range->value.len < 7
            || ngx_strncasecmp(r->headers_in.range->value.data, 
                (u_char *)"bytes=", 6)) {
        range_id = 0;
        temp_len = r->uri.len + 2;
    } else {
        /* process Range header */
        range_id = ngx_http_url_hash_range_parse(r, &len);
        if (range_id < 0) {
            range_id = 0;
        }
        range_id /= ctx->slice_size;
        temp_len = r->uri.len + len + 1;
    }

    url_range = (u_char *)ngx_pcalloc(r->pool, temp_len);
    if (url_range == NULL) {
        return 0;
    }
    ngx_snprintf(url_range, temp_len, "%V-%d", &r->uri, range_id);
    index = ngx_crc32_short(url_range, ngx_strlen(url_range));

    switch (ctx->strategy) {
        case STRATEGY_CHASH:
            index = ngx_http_url_hash_chash_find(ctx, index);
            break;
        case STRATEGY_WHASH:
            index = ngx_http_url_hash_whash_find(ctx, index);
            break;
        case STRATEGY_HASH:
            /* fall through, set STRATEGY_HASH default */
        default:
            index = index % ctx->backends->nelts;
            break;
    }
    return index;
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
    server_info *si = urlhash->backends->elts;

    nelts = urlhash->backends->nelts;
    index = ngx_http_request_hash_index(r, urlhash);
    host_len = si[index].host.len;
    len = http_len + host_len + r->uri.len;
    location = ngx_pcalloc(r->pool, len + 1);
    if (location == NULL) {
        goto error;
    }

    ngx_memzero(location, len + 1);

    ngx_memcpy(location, "http://", http_len);
    offset += http_len;
    ngx_memcpy(location + offset, si[index].host.data, host_len);
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
    uh->slice_size = ctx.slice_size;
    uh->strategy = ctx.strategy;

    switch (uh->strategy) {
        case STRATEGY_CHASH:
            if (ngx_http_url_hash_chash_init(uh, cf->pool) < 0) {
                rv = NGX_CONF_ERROR;
            }
            break;
        case STRATEGY_WHASH:
            if (ngx_http_url_hash_whash_init(uh, cf->pool) < 0) {
                rv = NGX_CONF_ERROR;
            }
            break;
        case STRATEGY_HASH:
            /* fall through */
        default:
            /* nothing */
            break;
    }
    ngx_destroy_pool(pool);
    return rv;
}
