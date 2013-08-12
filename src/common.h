#ifndef S3FS_COMMON_H_
#define S3FS_COMMON_H_

#include "crypto.h"

//
// Macro
//
#define SYSLOGINFO(...) syslog(LOG_INFO, __VA_ARGS__);
#define SYSLOGERR(...)  syslog(LOG_ERR, __VA_ARGS__);
#define SYSLOGCRIT(...) syslog(LOG_CRIT, __VA_ARGS__);

#define SYSLOGDBG(...) \
        if(debug){ \
          syslog(LOG_DEBUG, __VA_ARGS__); \
        }

#define SYSLOGDBGERR(...) \
        if(debug){ \
          syslog(LOG_ERR, __VA_ARGS__); \
        }

#define FGPRINT(...) \
       if(foreground){ \
          printf(__VA_ARGS__); \
       }

#define FGPRINT2(...) \
       if(foreground2){ \
          printf(__VA_ARGS__); \
       }

#define SAFESTRPTR(strptr) (strptr ? strptr : "")

//
// Typedef
//
typedef std::map<std::string, std::string> headers_t;

//
// Global valiables
//
extern bool debug;
extern bool foreground;
extern bool foreground2;
extern bool nomultipart;
extern bool encrypt_tmp_files;
extern std::string program_name;
extern std::string service_path;
extern std::string host;
extern std::string bucket;
extern std::string mount_prefix;

extern s3fs::Crypto *crypto;

#endif // S3FS_COMMON_H_
