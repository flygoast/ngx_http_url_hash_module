/*
 * Copyright (c) 2013, FengGu <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <math.h>


#define DEFAULT_SLICE_SIZE      (1024 * 1024 * 10)   /* 10M */

#define STRATEGY_HASH           1   /* general hashing method */
#define STRATEGY_WHASH          2   /* weighed hashing */
#define STRATEGY_CHASH          3   /* consistent hashing */

#define DEFAULT_STRATEGY        STRATEGY_CHASH


static ngx_conf_enum_t ngx_strategies[] = {
    { ngx_string("hash"), STRATEGY_HASH },
    { ngx_string("whash"), STRATEGY_WHASH },
    { ngx_string("chash"), STRATEGY_CHASH },
    { ngx_null_string, 0}
};


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
    ngx_uint_t       slice_size;
    ngx_uint_t       strategy;
} ngx_http_url_hash_conf_ctx_t;


typedef struct {
    ngx_array_t     *backends;
    ngx_array_t     *whash_space;
    ngx_array_t     *chash_continuum;
    ngx_uint_t       slice_size;
    ngx_uint_t       strategy;
} ngx_http_url_hash_loc_conf_t;


typedef int(*vnodecmp_pt)(const void *, const void *);

static ngx_int_t ngx_http_url_hash_handler(ngx_http_request_t *r);
static void ngx_md5(u_char *result, u_char *data);
static int ngx_http_url_hash_vnode_cmp(chash_vnode *a, chash_vnode *b);
static ngx_int_t ngx_http_url_hash_whash_init(
    ngx_http_url_hash_loc_conf_t *ulcf, ngx_pool_t *pool);
static ngx_int_t ngx_http_url_hash_whash_find(
    ngx_http_url_hash_loc_conf_t *ulcf, ngx_int_t idx);
static ngx_int_t ngx_http_url_hash_chash_init(
    ngx_http_url_hash_loc_conf_t *ulcf, ngx_pool_t *pool);
static ngx_int_t ngx_http_url_hash_chash_find(
    ngx_http_url_hash_loc_conf_t *ulcf, ngx_int_t idx);
static ngx_int_t ngx_http_url_hash_parse_strategy(ngx_str_t *value);
static char *ngx_http_url_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_request_hash_index(ngx_http_request_t *r,
    ngx_int_t *idx);
static ngx_int_t ngx_http_url_hash_get_location(ngx_http_request_t *r,
    ngx_str_t *loc);
static char *ngx_http_url_hash_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_url_hash_init(ngx_conf_t *cf);
static void *ngx_http_url_hash_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_url_hash_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_url_hash_range_parse(ngx_http_request_t *r,
    ngx_int_t *len);


static ngx_command_t ngx_http_url_hash_commands[] = {

    { ngx_string("url_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK
                        |NGX_CONF_NOARGS,
      ngx_http_url_hash_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_url_hash_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_url_hash_init,             /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_url_hash_create_loc_conf,  /* create location configuration */
    ngx_http_url_hash_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_url_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_url_hash_module_ctx,      /* module context */
    ngx_http_url_hash_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_url_hash_handler(ngx_http_request_t *r)
{
    ngx_str_t                      location;
    ngx_http_url_hash_loc_conf_t  *ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_url_hash_module);
    if (ulcf->strategy == NGX_CONF_UNSET_UINT 
        || ulcf->backends == NGX_CONF_UNSET_PTR)
    {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    if (ngx_http_url_hash_get_location(r, &location) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_clear_location(r);

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = location;

    return NGX_HTTP_MOVED_TEMPORARILY;
}


static void
ngx_md5(u_char result[16], u_char *data)
{
    ngx_md5_t md5;
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, ngx_strlen(data));
    ngx_md5_final(result, &md5);
}


static int 
ngx_http_url_hash_vnode_cmp(chash_vnode *a, chash_vnode *b)
{
    return (a->point < b->point) ? -1 : ((a->point > b->point) ? 1 : 0);
}


static ngx_int_t
ngx_http_url_hash_whash_init(ngx_http_url_hash_loc_conf_t *ulcf,
    ngx_pool_t *pool)
{
    ngx_uint_t      i;
    ngx_int_t       j;
    ngx_int_t      *weight;
    server_info    *si = ulcf->backends->elts;

    ulcf->whash_space = ngx_array_create(pool, 4, sizeof(ngx_int_t));
    if (ulcf->whash_space == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < ulcf->backends->nelts; ++i) {
        weight = ngx_array_push_n(ulcf->whash_space, si[i].weight);
        for (j = 0; j < si[i].weight; ++j) {
            weight[j] = i;
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_url_hash_whash_find(ngx_http_url_hash_loc_conf_t *ulcf,
    ngx_int_t index)
{
    ngx_int_t *idx = ulcf->whash_space->elts;
    return idx[index % ulcf->whash_space->nelts];
}


static ngx_int_t
ngx_http_url_hash_chash_init(ngx_http_url_hash_loc_conf_t *ctx, 
    ngx_pool_t *pool)
{
    ngx_uint_t      i, j, k, nvnode;
    ngx_int_t       total_weight = 0;
    server_info    *si = ctx->backends->elts;
    chash_vnode    *vnode;
    float           percent;
    u_char          temp_vnode[128];
    u_char          result[16];

    ctx->chash_continuum = ngx_array_create(pool, 4, sizeof(chash_vnode));
    if (ctx->chash_continuum == NULL) {
        return NGX_ERROR;
    }

    /* calculate total weight */
    for (i = 0; i < ctx->backends->nelts; ++i) {
        total_weight += si[i].weight;
    }

    /* generate the consistent hash continuum */
    for (i = 0; i < ctx->backends->nelts; ++i) {
        percent = (float)si[i].weight / (float)total_weight;
        nvnode = floorf(percent * 40.0 * (float)ctx->backends->nelts);

        j = 0;
        for (j = 0; j < nvnode; ++j) {
            ngx_snprintf(temp_vnode, 128, "%V-%d", &si[i].host, j);
            ngx_md5(result, temp_vnode);

            for (k = 0; k < 4; ++k) {
                vnode = ngx_array_push(ctx->chash_continuum);
                if (vnode == NULL) {
                    return NGX_ERROR;
                }
                vnode->point = (result[3 + k * 4] << 24)
                               |(result[2 + k * 4] << 16)
                               |(result[1 + k * 4] << 8)
                               |(result[k * 4]);
                vnode->index = i;
            }
        }
    }

    /* sort in ascending order of "point" */
    qsort((void *)ctx->chash_continuum->elts, 
          ctx->chash_continuum->nelts, 
          sizeof(chash_vnode), 
          (vnodecmp_pt)ngx_http_url_hash_vnode_cmp);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_url_hash_chash_find(ngx_http_url_hash_loc_conf_t *ulcf,
    ngx_int_t index)
{
    uint32_t        hash = index & 0xffffffff;
    ngx_uint_t      highp = ulcf->chash_continuum->nelts;
    ngx_uint_t      lowp = 0, midp;
    ngx_uint_t      midval, midval1;
    chash_vnode    *vnodes = ulcf->chash_continuum->elts;

    /* divide and conquer array search to find server with next
     * biggest point after what this key hashes to */
    while (1) {
        midp = (ngx_int_t)((lowp + highp) / 2);
        if (midp == ulcf->chash_continuum->nelts) {
            return vnodes[0].index; /* if at the end, roll back to zeroth */
        }

        midval = vnodes[midp].point;
        midval1 = (midp == 0 ? 0 : vnodes[midp - 1].point);
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


static ngx_int_t
ngx_http_url_hash_parse_strategy(ngx_str_t *value)
{
    ngx_conf_enum_t     *e = ngx_strategies;
    ngx_uint_t           i;

    for (i = 0; e[i].name.len != 0; ++i) {
        if (e[i].name.len != value->len 
            || ngx_strcasecmp(e[i].name.data, value->data) != 0)
        {
            continue;
        }

        return e[i].value;
    }

    return DEFAULT_STRATEGY;
}


static char *
ngx_http_url_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
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

        if (ctx->backends == NGX_CONF_UNSET_PTR) {
            ctx->backends = ngx_array_create(ctx->pool, 4, 
                                             sizeof(server_info));
            if (ctx->backends == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        si = ngx_array_push(ctx->backends);
        if (si == NULL) {
            return NGX_CONF_ERROR;
        }

        si->host.data = ngx_pstrdup(ctx->pool, &value[1]);
        if (si->host.data == NULL) {
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
            || ctx->slice_size == 0)
        {
            ctx->slice_size = DEFAULT_SLICE_SIZE; /* default size 10K */
        }

    } else if (ngx_strcmp(value[0].data, "strategy") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of strategy parameters");
            return NGX_CONF_ERROR;
        }

        ctx->strategy = ngx_http_url_hash_parse_strategy(&value[1]);

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid url_hash parameters");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_request_hash_index(ngx_http_request_t *r, ngx_int_t *idx) 
{
    ngx_http_url_hash_loc_conf_t  *ulcf;
    u_char                        *url_range;
    ngx_uint_t                     temp_len;
    ngx_int_t                      range_id;
    ngx_int_t                      index;
    ngx_int_t                      len;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_url_hash_module);

    if (r->headers_in.range == NULL 
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data, 
                           (u_char *)"bytes=", 6))
    {
        range_id = 0;
        temp_len = r->uri.len + 2;
    } else {
        /* process Range header */
        range_id = ngx_http_url_hash_range_parse(r, &len);
        if (range_id < 0) {
            range_id = 0;
        }
        range_id /= ulcf->slice_size;
        temp_len = r->uri.len + len + 1;
    }

    url_range = (u_char *)ngx_pcalloc(r->pool, temp_len);
    if (url_range == NULL) {
        return NGX_ERROR;
    }
    ngx_snprintf(url_range, temp_len, "%V-%d", &r->uri, range_id);
    index = ngx_crc32_short(url_range, ngx_strlen(url_range));

    switch (ulcf->strategy) {
        case STRATEGY_CHASH:
            index = ngx_http_url_hash_chash_find(ulcf, index);
            break;
        case STRATEGY_WHASH:
            index = ngx_http_url_hash_whash_find(ulcf, index);
            break;
        case STRATEGY_HASH:
            /* fall through, set STRATEGY_HASH default */
        default:
            index = index % ulcf->backends->nelts;
            break;
    }
    *idx = index;

    return NGX_OK;
}


static ngx_int_t
ngx_http_url_hash_get_location(ngx_http_request_t *r, ngx_str_t *loc)
{
    ngx_http_url_hash_loc_conf_t  *ulcf;
    server_info                   *si;
    ngx_uint_t                     nelts;
    ngx_uint_t                     len;
    ngx_uint_t                     offset;
    ngx_uint_t                     http_len = sizeof("http://") - 1;
    ngx_uint_t                     host_len;
    ngx_int_t                      index;
    u_char                        *location;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_url_hash_module);
    si = ulcf->backends->elts;
    nelts = ulcf->backends->nelts;

    if (ngx_http_request_hash_index(r, &index) != NGX_OK) {
        return NGX_ERROR;
    }

    host_len = si[index].host.len;
    len = http_len + host_len + r->uri.len;
    location = ngx_pcalloc(r->pool, len + 1);
    if (location == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(location, "http://", http_len);
    offset = http_len;
    ngx_memcpy(location + offset, si[index].host.data, host_len);
    offset += host_len;
    if (location[offset - 1] == '/') {
        --offset; /* uri partion has a '/', so eliminate it. */
    }
    ngx_memcpy(location + offset, r->uri.data, r->uri.len);
    offset += r->uri.len;

    loc->len = len;
    loc->data = location;

    return NGX_OK;
}


static char *
ngx_http_url_hash_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                            *rv;
    ngx_str_t                       *value;
    ngx_http_url_hash_loc_conf_t    *ulcf;
    ngx_pool_t                      *pool;
    ngx_conf_t                       save;
    ngx_http_url_hash_conf_ctx_t     ctx;

    ulcf = conf;
    value = cf->args->elts;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ctx, sizeof(ngx_http_url_hash_conf_ctx_t));
    ctx.pool = cf->pool;
    ctx.backends = NGX_CONF_UNSET_PTR;
    
    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = ngx_http_url_hash;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    ulcf->backends = ctx.backends;
    if (ulcf->backends == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no backend specified");
        ngx_destroy_pool(pool);
        return NGX_CONF_ERROR;
    }

    ulcf->slice_size = ctx.slice_size;
    ulcf->strategy = ctx.strategy;

    switch (ulcf->strategy) {
    case STRATEGY_CHASH:
        if (ngx_http_url_hash_chash_init(ulcf, cf->pool) != NGX_OK) {
            rv = NGX_CONF_ERROR;
        }
        break;
    case STRATEGY_WHASH:
        if (ngx_http_url_hash_whash_init(ulcf, cf->pool) != NGX_OK) {
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


static ngx_int_t
ngx_http_url_hash_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_url_hash_handler;

    return NGX_OK;
}


static void *
ngx_http_url_hash_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_url_hash_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_url_hash_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->backends = NGX_CONF_UNSET_PTR;
    conf->whash_space = NGX_CONF_UNSET_PTR;
    conf->chash_continuum = NGX_CONF_UNSET_PTR;
    conf->slice_size = NGX_CONF_UNSET_UINT;
    conf->strategy = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_url_hash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_url_hash_loc_conf_t *prev = parent;
    ngx_http_url_hash_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->strategy, prev->strategy, 
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->slice_size, prev->slice_size, 
                              NGX_CONF_UNSET_UINT);

    ngx_conf_merge_ptr_value(conf->backends, prev->backends,
                             NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->whash_space, prev->whash_space,
                             NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->chash_continuum, prev->chash_continuum,
                             NGX_CONF_UNSET_PTR);
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_url_hash_range_parse(ngx_http_request_t *r, ngx_int_t *len)
{
    u_char            *p;
    ngx_int_t          start = 0;

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
