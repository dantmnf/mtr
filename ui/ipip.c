#include "config.h"

#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <curl/curl.h>
#include "3rdparty/cJSON.h"

#include "mtr.h"
#include "dns.h"
#include "net.h"
#include "utils.h"

struct buffer_ctx
{
    char *buf;
    size_t buflen;
    size_t content_len;
};

static void *buffer_init(struct buffer_ctx *bufctx)
{
    bufctx->buf = malloc(4096);
    bufctx->buflen = 4096;
    bufctx->content_len = 0;
    return bufctx->buf;
}

static void *buffer_append(struct buffer_ctx *bufctx, const char *data, size_t len)
{
    if (bufctx->content_len + len <= bufctx->buflen)
    {
        memmove(bufctx->buf + bufctx->content_len, data, len);
        bufctx->content_len += len;
        return bufctx->buf;
    }
    else
    {
        size_t newlen = bufctx->buflen + (len > 4096 ? len : 4096);
        char *newbuf = realloc(bufctx->buf, newlen);
        if (newbuf)
        {
            bufctx->buf = newbuf;
            bufctx->buflen = newlen;
            memmove(bufctx->buf + bufctx->content_len, data, len);
            bufctx->content_len += len;
            return bufctx->buf;
        }
        return NULL;
    }
}

static void buffer_free(struct buffer_ctx *bufctx)
{
    free(bufctx->buf);
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct buffer_ctx *bufctx = (struct buffer_ctx *)userdata;
    if (buffer_append(bufctx, ptr, size * nmemb))
        return size * nmemb;
    return 0;
}

int ipip_lookup(struct mtr_ctl *ctl, char *buf, size_t buflen, ip_t *ip, const char *host)
{
    char request_url[4096];
    int urllen;
    int result = 0;
    if (ctl->af == AF_INET6)
        return 0;
    urllen = snprintf(request_url, 4096, "http://btapi.ipip.net/host/info?ip=%s&host=%s", strlongip(ctl, ip), host ?: "");
    if (urllen < 4096)
    {
        CURL *curl = curl_easy_init();
        if (curl)
        {
            CURLcode res;
            struct buffer_ctx bufctx;
            buffer_init(&bufctx);

            curl_easy_setopt(curl, CURLOPT_URL, request_url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bufctx);
            res = curl_easy_perform(curl);
            if (res == CURLE_OK)
            {
                cJSON *jdoc, *asn, *area;
                char *asnstr = "", *areastr = "";
                int cols = 0;
                char *pos;
                size_t len;
                buffer_append(&bufctx, "" /*\x00*/, 1);
                jdoc = cJSON_Parse(bufctx.buf);
                asn = cJSON_GetObjectItemCaseSensitive(jdoc, "as");
                area = cJSON_GetObjectItemCaseSensitive(jdoc, "area");
                if (cJSON_IsString(asn))
                    asnstr = asn->valuestring;
                if (cJSON_IsString(area))
                    areastr = xstrdup(area->valuestring);

                while (cols < 5)
                {
                    pos = strchr(areastr, '\t');
                    if(pos == NULL)
                        break;
                    *pos = ' ';
                    cols++;
                }
                *pos = 0;

                pos = areastr;
                while ((pos = strstr(pos, "  ")))
                {
                    memmove(pos, pos + 1, strlen(pos));
                }

                while ((len = strlen(areastr), areastr[len - 1] == ' '))
                    areastr[len - 1] = 0;

                result = snprintf(buf, buflen, "%s %s", areastr, asnstr);
                free(areastr);
                cJSON_Delete(jdoc);
            }
            curl_easy_cleanup(curl);
            buffer_free(&bufctx);
        }
    }
    return result;
}
