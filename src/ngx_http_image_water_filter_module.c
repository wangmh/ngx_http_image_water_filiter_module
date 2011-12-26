/*
 * ngx_http_image_water_filter_module.c
 *
 *  Created on: 2011-12-25
 *      Author: saint
 */

/*
 * Copyright (C) Igor Sysoev
 */

/*
 * image_water /home/bin/image_water
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <wand/MagickWand.h>


#define NGX_HTTP_IMAGE_WATER_NONE      0
#define NGX_HTTP_IMAGE_WATER_JPEG      1
#define NGX_HTTP_IMAGE_WATER_GIF       2
#define NGX_HTTP_IMAGE_WATER_PNG       3

#define NGX_HTTP_IMAGE_WATER_START     0
#define NGX_HTTP_IMAGE_WATER_READ      1
#define NGX_HTTP_IMAGE_WATER_PROCESS   2
#define NGX_HTTP_IMAGE_WATER_PASS      3
#define NGX_HTTP_IMAGE_WATER_DONE      4


#define NGX_HTTP_IMAGE_WATER_BUFFERED  0x08

#define IMAGE_WATER_ThrowWandException(wand) \
{ \
  char \
    *description; \
 \
  ExceptionType \
    severity; \
 \
  description=MagickGetException(wand,&severity); \
 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,\
                    "%s %s %lu %s\n", GetMagickModule(),description);\
  description=(char *) MagickRelinquishMemory(description); \
}

/*
 * module的配置文件
 */
typedef struct
{
	u_char *image_water;
	size_t len;
	size_t	buffer_size;
	ngx_flag_t enable;
} ngx_http_image_water_filter_conf_t;


/*
 * module的在某个访问内存在的上下文
 */
typedef struct {
    u_char                      *image;
    u_char                      *last;

    ngx_uint_t                   type;
    ngx_uint_t                   phase;
    size_t                       length;

} ngx_http_image_water_filter_ctx_t;




static ngx_int_t ngx_http_image_water_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_image_water_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_uint_t ngx_http_image_water_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_image_water_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_image_water_process(ngx_http_request_t *r);
static void ngx_http_image_water_length(ngx_http_request_t *r, ngx_buf_t *b);

static ngx_int_t ngx_http_image_water_send(ngx_http_request_t *r,
		ngx_http_image_water_filter_ctx_t *ctx, ngx_chain_t *in);

static void *ngx_http_image_water_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_image_water_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
//
static ngx_int_t ngx_http_image_water_filter_process_init(ngx_cycle_t *cycle);
static void ngx_http_image_water_filter_process_exit(ngx_cycle_t *cycle);

static char *ngx_http_image_water_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_image_water_filter_init(ngx_conf_t *cf);




/*
 * 命令参数  image_water /home/bin/image_water
 */
static ngx_command_t ngx_http_image_water_filter_commands[] =
{
	{
		ngx_string("image_water"),
		NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_http_image_water_filter,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
    {
    	ngx_string("image_buffer_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_image_water_filter_conf_t, buffer_size),
        NULL
    },
	ngx_null_command
};

//回调函数
static ngx_http_module_t  ngx_http_image_water_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_image_water_filter_init,            /* postconfiguration 初始化*/

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_image_water_filter_create_conf,     /* create location configuration */
    ngx_http_image_water_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_image_water_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_image_water_filter_module_ctx,     /* module context */
    ngx_http_image_water_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_image_water_filter_process_init, /* init process */
    NULL,                                  	  /* init thread */
    NULL,                                  	  /* exit thread */
    ngx_http_image_water_filter_process_exit, /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter; //保存当前链接
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;//保存当前的内容链接



static ngx_str_t  ngx_http_image_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png")
};


// 头部过滤
static ngx_int_t ngx_http_image_water_header_filter(ngx_http_request_t *r)
{
	off_t len;
	ngx_http_image_water_filter_ctx_t *ctx;
	ngx_http_image_water_filter_conf_t *conf;



	ctx = ngx_http_get_module_ctx(r, ngx_http_image_water_filter_module);

	if(ctx){
		ngx_http_set_ctx(r, NULL, ngx_http_image_water_filter_module);
		return ngx_http_next_header_filter(r);
	}




	//copy form image_filter maybe multipart special
    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

	conf = ngx_http_get_module_loc_conf(r, ngx_http_image_water_filter_module);

	if(r->headers_out.status == NGX_HTTP_NOT_MODIFIED || !conf->enable){
		return ngx_http_next_header_filter(r);
	}


    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_image_water_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_image_water_filter_module);
    len = r->headers_out.content_length_n;

    //如果处理的图片超过了最大的限制，错误。
    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    if (len == -1) {
    	ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }
    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }
    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;
    return NGX_OK;
}



static ngx_int_t ngx_http_image_water_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_int_t 							rc;
	ngx_str_t 							*ct;
	ngx_chain_t 						out;
	ngx_http_image_water_filter_ctx_t 	*ctx;
	ngx_http_image_water_filter_conf_t  *conf;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image water filter")

	if(in == NULL){
		return ngx_http_next_body_filter(r, in);
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_image_water_filter_module);
	if(ctx == NULL){
		return ngx_http_next_body_filter(r, in);
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_image_water_filter_module);


	switch(ctx->type){

	case NGX_HTTP_IMAGE_WATER_START:

		ctx->type = ngx_http_image_water_test(r, in);
		//如果不是图片
		if(NGX_HTTP_IMAGE_WATER_NONE == ctx->type){
			return ngx_http_filter_finalize_request(r,
				&ngx_http_image_water_filter_module,
				NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
		}

        /* override content type */
		ct = &ngx_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        ctx->phase = NGX_HTTP_IMAGE_WATER_READ;

        /* fall through */
	case NGX_HTTP_IMAGE_WATER_READ:
		rc = ngx_http_image_water_read(r, in);

		if(rc == NGX_AGAIN){
			return NGX_OK;
		}

		if (rc == NGX_ERROR) {
			return ngx_http_filter_finalize_request(r,
				&ngx_http_image_water_filter_module,
		        NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
		}
		/* fall through */

	case NGX_HTTP_IMAGE_WATER_PROCESS:
		out.buf = ngx_http_image_water_process(r);
		if (out.buf == NULL) {
			return ngx_http_filter_finalize_request(r,
				&ngx_http_image_water_filter_module,
		        NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
		}

		out.next = NULL;
		ctx->phase = NGX_HTTP_IMAGE_WATER_PASS;
		return ngx_http_image_water_send(r, ctx, &out);

	case NGX_HTTP_IMAGE_WATER_PASS:
		return ngx_http_next_body_filter(r, in);

	default:
		rc = ngx_http_next_body_filter(r, NULL);
		return (rc == NGX_OK) ? NGX_ERROR : rc;
	}
}

static void ngx_http_image_cleanup(void *data)
{
	ngx_free(data);
}


static ngx_buf_t *ngx_http_image_water_process(ngx_http_request_t *r)
{
    ngx_http_image_water_filter_ctx_t   *ctx;
    ngx_http_image_water_filter_conf_t  *conf;
    ngx_buf_t                    		*b;
    MagickWand 							*magick_wand_src;
    MagickWand							*magick_wand_water;
    MagickBooleanType					 status;



    r->connection->buffered &= ~NGX_HTTP_IMAGE_WATER_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_water_filter_module);

    conf =  ngx_http_get_module_loc_conf(r, ngx_http_image_water_filter_module);

    magick_wand_src = NewMagickWand();
    magick_wand_water = NewMagickWand();
    status = MagickReadImageBlob(magick_wand_src, ctx->image, ctx->length);
    ngx_pfree(r->pool, ctx->image);
    if(status == MagickFalse){
    	IMAGE_WATER_ThrowWandException(magick_wand_src);
    	return NULL;
    }
    status = MagickReadImageBlob(magick_wand_water, conf->image_water, conf->len);
    if(status == MagickFalse){
    	IMAGE_WATER_ThrowWandException(magick_wand_water);
    	return NULL;
    }


	size_t height = MagickGetImageHeight(magick_wand_src);
	size_t width = MagickGetImageWidth(magick_wand_src);

	RectangleInfo  geometry;

	Image *img = GetImageFromMagickWand(magick_wand_src);
	SetGeometry(img, &geometry);

	geometry.width= MagickGetImageWidth(magick_wand_water);
	geometry.height= MagickGetImageHeight(magick_wand_water);
	GravityAdjustGeometry(width, height, SouthEastGravity, &geometry);


	MagickSetImageArtifact(magick_wand_water, "compose:args", "80");
	status  = MagickCompositeImage(magick_wand_src, magick_wand_water, DissolveCompositeOp, geometry.x, geometry.y);
	if(status == MagickFalse){
	    	IMAGE_WATER_ThrowWandException(magick_wand_src);
	    	return NULL;
    }
	size_t image_size;
	u_char *image;
	image =  MagickGetImagesBlob(magick_wand_src, &image_size);

	magick_wand_src = DestroyMagickWand(magick_wand_src);
	magick_wand_water = DestroyMagickWand(magick_wand_water);

	ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
    	ngx_free(image);
        return NULL;
    }



    cln->handler = ngx_http_image_cleanup;
    cln->data = image;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
    	ngx_free(image);
    	return NULL;
    }

    b->pos = (u_char *) image;
    b->last = (u_char *) image + image_size;
    b->last_buf = 1;
    b->memory = 1;

    ngx_http_image_water_length(r, b);

    return b;
}

static void ngx_http_image_water_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}




static ngx_int_t ngx_http_image_water_send(ngx_http_request_t *r,
		ngx_http_image_water_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_IMAGE_WATER_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}



static ngx_uint_t ngx_http_image_water_test(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_IMAGE_WATER_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NGX_HTTP_IMAGE_WATER_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NGX_HTTP_IMAGE_WATER_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NGX_HTTP_IMAGE_WATER_PNG;
    }

    return NGX_HTTP_IMAGE_WATER_NONE;
}


/*
 * 创建参数
 */
static void *ngx_http_image_water_filter_create_conf(ngx_conf_t *cf)
{
	ngx_http_image_water_filter_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_water_filter_conf_t));
	if(conf == NULL){
		return NULL;
	}
	conf->len = NGX_CONF_UNSET_SIZE;
	conf->image_water = NGX_CONF_UNSET_PTR;
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
	conf->enable = NGX_CONF_UNSET;
	return conf;
}

/*
 * copy from ngx_image_filter
 * 每个chain_t不一定包含完整的image_buf所以可能返回NGX_AGAIN
 */
static ngx_int_t ngx_http_image_water_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_image_water_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_water_filter_module);

    //第一个位置
    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }
        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image_water buf: %uz", size);

        rest = ctx->image + ctx->length - p;
        size = (rest < size) ? rest : size;

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_IMAGE_WATER_BUFFERED;

    return NGX_AGAIN;
}


/*
 * 合并参数
 */
static char *ngx_http_image_water_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_image_water_filter_conf_t *prev = parent;
	ngx_http_image_water_filter_conf_t *conf = child;

	ngx_conf_merge_size_value(conf->len, conf->len, NGX_CONF_UNSET_SIZE);
	ngx_conf_merge_ptr_value(conf->image_water, prev->image_water, NULL);
	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	if(conf->image_water == NULL || conf->len == NGX_CONF_UNSET_SIZE){
		conf->enable = 0;
	}


    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);
	return NGX_CONF_OK;
}

/*
 * 初始化imageMagick的环境
 */
static ngx_int_t ngx_http_image_water_filter_process_init(ngx_cycle_t *cycle)
{
	MagickWandGenesis();
	return NGX_OK;
}

/*
 * 释放imageMagick的环境
 */
static void ngx_http_image_water_filter_process_exit(ngx_cycle_t *cycle)
{
	MagickWandTerminus();
	return;
}

/*
 * 初始化水印图片
 */
static char *ngx_http_image_water_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_image_water_filter_conf_t	*imcf = conf;
	ngx_str_t						   	*value;
	struct 								stat file_stat;
	int 								fd;
	int 								i = 1;

	value = cf->args->elts;
	off_t pa_offset = 0 & ~(sysconf(_SC_PAGE_SIZE) - 1);

	fd = open((const char *)value[i].data, O_RDONLY);
	if(fd < 0){
		goto failed;
	}

	memset(&file_stat, 0, sizeof(file_stat));
	if (stat((const char *)value[i].data, &file_stat) != 0) {
		goto failed;
	} else {
		imcf->len = file_stat.st_size;
	}
	imcf->image_water = mmap(NULL, imcf->len - pa_offset, PROT_READ,
			MAP_SHARED, fd, pa_offset);
	if (imcf->image_water == MAP_FAILED)
		goto failed;
	imcf->enable = 1;
	return NGX_CONF_OK;

failed:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "open file error \"%V\"", &value[i]);
	return NGX_CONF_ERROR;
}


/*
 * 参考ngx_image_filter,链表结构，将top由next_header代理，top重新制定到输出上
 */
static ngx_int_t ngx_http_image_water_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_image_water_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_image_water_body_filter;

    return NGX_OK;
}


