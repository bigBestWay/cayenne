#include <linux/module.h>
#include <linux/slab.h>
#include "handler.h"
#include "base64.h"

typedef int (*CMD_HANDLE)(int argc, const char * argvs[], char * out, int maxSize);
static int handle_list(int argc, const char * argvs[], char * out, int maxSize);
static int handle_readfile(int argc, const char * argvs[], char * out, int maxSize);
static int handle_shell(int argc, const char * argvs[], char * out, int maxSize);
static int handle_filestat(int argc, const char * argvs[], char * out, int maxSize);

static struct {
    const char * key;
    CMD_HANDLE handle;
} _cmd_table[] = {
    {"list", handle_list},
    {"readfile", handle_readfile},
    {"shell", handle_shell},
    {"filestat", handle_filestat}
};

static CMD_HANDLE find_handler(const char * cmd)
{
    if(cmd == NULL)
        return NULL;
    
    int i = 0;
    for (; i < sizeof(_cmd_table)/sizeof(_cmd_table[0]); i++)
    {
        if(strcmp(cmd, _cmd_table[i].key) == 0)
            return _cmd_table[i].handle;
    }
    return NULL;
}

static int parseCmdLine(char * cmdline, const char *argv[], int max)
{
    int argc = 0;
    int findWord = 0;
    int i = 0;
    for (i = 0; cmdline[i] != 0 && argc <= max; i++)
    {
        if (cmdline[i] != ' ' && cmdline[i] != '\n')
        {
        	if(findWord == 0)
        	{
        		argv[argc++] = &cmdline[i];
			}
            findWord = 1;
        }
        else
        {
            cmdline[i] = 0;
            findWord = 0;
        }
    }
    return argc;
}

static void make_respone(const char * data, int len, char * out, int size)
{
    int rsplen = BASE64_ENCODE_OUT_SIZE(len);
    if(size > rsplen)
    {
        base64_encode(data, len, out);
    }
}

/* 处理命令，带出响应 */
int handle_cmd(const char * data, char * out, int size)
{
    int ret = 0;
    int inlen = strlen(data);
    char * cmd = kmalloc(BASE64_DECODE_OUT_SIZE(inlen), GFP_KERNEL);
    memset(cmd, 0, BASE64_DECODE_OUT_SIZE(inlen));
    if(base64_decode(data, inlen, cmd) == 0)
    {
        ret = sizeof("base64decode error")-1;
        make_respone("base64decode error", ret, out, size);
        goto exit;
    }

    const char * argv[5] = {NULL};
    int argc = parseCmdLine(cmd, argv, 5);
    CMD_HANDLE handle = find_handler(argv[0]);
    if(argc == 0 || handle == NULL)
    {
        ret = sizeof("unkown cmd") - 1;
        make_respone("unkown cmd", ret, out, size);
        goto exit;
    }

    ret = handle(argc, argv, out, size);
exit:
    kfree(cmd);
    return ret;
}

static int handle_list(int argc, const char * argvs[], char * out, int maxSize)
{
    int ret = sizeof("handle_list") - 1;
    memcpy(out, "handle_list", ret);
    return ret;
}

static int handle_readfile(int argc, const char * argvs[], char * out, int maxSize)
{
    int ret = sizeof("handle_readfile") - 1;
    memcpy(out, "handle_readfile", ret);
    return ret;
}

static int handle_shell(int argc, const char * argvs[], char * out, int maxSize)
{
    int ret = sizeof("handle_shell") - 1;
    memcpy(out, "handle_shell", ret);
    return ret;
}

static int handle_filestat(int argc, const char * argvs[], char * out, int maxSize)
{
    int ret = sizeof("handle_filestat") - 1;
    memcpy(out, "handle_filestat", ret);
    return ret;
}

EXPORT_SYMBOL(handle_cmd);
