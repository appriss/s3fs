/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <algorithm>
#include <list>

#include "common.h"
#include "curl.h"
#include "string_util.h"
#include "s3fs.h"
#include "s3fs_util.h"

using namespace std;

//-------------------------------------------------------------------
// Typedef
//-------------------------------------------------------------------
struct case_insensitive_compare_func {
  bool operator ()(const string &a, const string &b) {
    return strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};
typedef map<string, string, case_insensitive_compare_func> mimes_t;
typedef pair<double, double> progress_t;

//-------------------------------------------------------------------
// Static valiables
//-------------------------------------------------------------------
static pthread_mutex_t curl_handles_lock;
static pthread_mutex_t curl_share_lock;
static CURLSH* hCurlShare = NULL;
static const EVP_MD* evp_md = EVP_sha1();
static map<CURL*, time_t> curl_times;
static map<CURL*, progress_t> curl_progress;
static string curl_ca_bundle;
static mimes_t mimeTypes;

//-------------------------------------------------------------------
// Class BodyData
//-------------------------------------------------------------------
#define BODYDATA_RESIZE_APPEND_MIN  (1 * 1024)         // 1KB
#define BODYDATA_RESIZE_APPEND_MID  (1 * 1024 * 1024)  // 1MB
#define BODYDATA_RESIZE_APPEND_MAX  (10 * 1024 * 1024) // 10MB

bool BodyData::Resize(size_t addbytes)
{
  if(IsSafeSize(addbytes)){
    return true;
  }
  // New size
  size_t need_size = (lastpos + addbytes + 1) - bufsize;
  if(BODYDATA_RESIZE_APPEND_MAX < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MAX < need_size ? need_size : BODYDATA_RESIZE_APPEND_MAX);
  }else if(BODYDATA_RESIZE_APPEND_MID < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MID < need_size ? need_size : BODYDATA_RESIZE_APPEND_MID);
  }else if(BODYDATA_RESIZE_APPEND_MIN < bufsize){
    need_size = ((bufsize * 2) < need_size ? need_size : (bufsize * 2));
  }else{
    need_size = (BODYDATA_RESIZE_APPEND_MIN < need_size ? need_size : BODYDATA_RESIZE_APPEND_MIN);
  }
  // realloc
  if(NULL == (text = (char*)realloc(text, (bufsize + need_size)))){
    FGPRINT("BodyData::Resize() not enough memory (realloc returned NULL)\n");
    SYSLOGDBGERR("not enough memory (realloc returned NULL)\n");
    return false;
  }
  bufsize += need_size;
  return true;
}

void BodyData::Clear(void)
{
  if(text){
    free(text);
    text = NULL;
  }
  lastpos = 0;
  bufsize = 0;
}

bool BodyData::Append(void* ptr, size_t bytes)
{
  if(!ptr){
    return false;
  }
  if(0 == bytes){
    return true;
  }
  if(!Resize(bytes)){
    return false;
  }
  memcpy(&text[lastpos], ptr, bytes);
  lastpos += bytes;
  text[lastpos] = '\0';

  return true;
}

const char* BodyData::str(void) const
{
  static const char* strnull = "";
  if(!text){
    return strnull;
  }
  return text;
}

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
int init_curl_handles_mutex(void)
{
  return pthread_mutex_init(&curl_handles_lock, NULL);
}

int destroy_curl_handles_mutex(void)
{
  return pthread_mutex_destroy(&curl_handles_lock);
}

bool init_curl_global_all(void)
{
  if(CURLE_OK != curl_global_init(CURL_GLOBAL_ALL)){
    FGPRINT("init_curl_global_all returns error.\n");
    SYSLOGERR("init_curl_global_all returns error.");
    return false;
  }
  return true;
}

void cleanup_curl_global_all(void)
{
  curl_global_cleanup();
}

static void lock_curl_share(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr)
{
  if(hCurlShare && useptr && CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_t* lockmutex = (pthread_mutex_t*)useptr;
    pthread_mutex_lock(lockmutex);
  }
}

static void unlock_curl_share(CURL* handle, curl_lock_data nLockData, void* useptr)
{
  if(hCurlShare && useptr && CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_t* lockmutex = (pthread_mutex_t*)useptr;
    pthread_mutex_unlock(lockmutex);
  }
}

int init_curl_share(bool isCache)
{
  CURLSHcode nSHCode;

  if(!isCache){
    return 0;
  }
  pthread_mutex_init(&curl_share_lock, NULL);

  if(NULL == (hCurlShare = curl_share_init())){
    FGPRINT(" init_curl_share: curl_share_init failed\n");
    SYSLOGERR("init_curl_share: curl_share_init failed\n");
    return -1;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(hCurlShare, CURLSHOPT_LOCKFUNC, lock_curl_share))){
    FGPRINT(" init_curl_share: curl_share_setopt(LOCKFUNC) returns %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    SYSLOGERR("init_curl_share: %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    return nSHCode;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(hCurlShare, CURLSHOPT_UNLOCKFUNC, unlock_curl_share))){
    FGPRINT(" init_curl_share: curl_share_setopt(UNLOCKFUNC) returns %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    SYSLOGERR("init_curl_share: %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    return nSHCode;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS))){
    FGPRINT(" init_curl_share: curl_share_setopt(DNS) returns %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    SYSLOGERR("init_curl_share: %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    return nSHCode;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(hCurlShare, CURLSHOPT_USERDATA, (void*)&curl_share_lock))){
    FGPRINT(" init_curl_share: curl_share_setopt(USERDATA) returns %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    SYSLOGERR("init_curl_share: %d(%s)\n", nSHCode, curl_share_strerror(nSHCode));
    return nSHCode;
  }
  return 0;
}

int destroy_curl_share(bool isCache)
{
  int result = 0;

  if(!isCache){
    return result;
  }
  if(hCurlShare && CURLSHE_OK != curl_share_cleanup(hCurlShare)){
    result = -1;
  }
  if(0 != pthread_mutex_destroy(&curl_share_lock)){
    result = -1;
  }
  return result;
}

void my_set_curl_share(CURL* curl)
{
  if(curl && hCurlShare){
    curl_easy_setopt(curl, CURLOPT_SHARE, hCurlShare);
  }
}

size_t header_callback(void *data, size_t blockSize, size_t numBlocks, void *userPtr)
{
  headers_t* headers = reinterpret_cast<headers_t*>(userPtr);
  string header(reinterpret_cast<char*>(data), blockSize * numBlocks);
  string key;
  stringstream ss(header);

  if (getline(ss, key, ':')) {
    // Force to lower, only "x-amz"
    string lkey = key;
    transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
    if(lkey.substr(0, 5) == "x-amz"){
      key = lkey;
    }
    string value;
    getline(ss, value);
    (*headers)[key] = trim(value);
  }
  return blockSize * numBlocks;
}

CURL *create_curl_handle(void)
{
  time_t now;
  CURL *curl_handle;

  pthread_mutex_lock(&curl_handles_lock);
  curl_handle = curl_easy_init();
  curl_easy_reset(curl_handle);
  curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, connect_timeout);
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(curl_handle, CURLOPT_PROGRESSFUNCTION, my_curl_progress);
  curl_easy_setopt(curl_handle, CURLOPT_PROGRESSDATA, curl_handle);
  // curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 1);
  
  if(ssl_verify_hostname.substr(0,1) == "0"){
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
  }
  if(curl_ca_bundle.size() != 0){
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO, curl_ca_bundle.c_str());
  }
  now = time(0);
  curl_times[curl_handle] = now;
  curl_progress[curl_handle] = progress_t(-1, -1);
  pthread_mutex_unlock(&curl_handles_lock);

  return curl_handle;
}

void destroy_curl_handle(CURL *curl_handle)
{
  if(curl_handle != NULL) {
    pthread_mutex_lock(&curl_handles_lock);
    curl_times.erase(curl_handle);
    curl_progress.erase(curl_handle);
    curl_easy_cleanup(curl_handle);
    pthread_mutex_unlock(&curl_handles_lock);
  }

  return;
}

int curl_delete(const char *path)
{
  int result;
  string date;
  string url;
  string my_url;
  string resource;
  auto_curl_slist headers;
  CURL *curl = NULL;

  resource = urlEncode(service_path + bucket + path);
  url = host + resource;
  date = get_date();

  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if(public_bucket.substr(0,1) != "1"){
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("DELETE", "", "", date, headers.get(), resource));
  }
  my_url = prepare_url(url.c_str());
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
  result = my_curl_easy_perform(curl);
  destroy_curl_handle(curl);

  return result;
}

int curl_get_headers(const char *path, headers_t &meta)
{
  int result;
  CURL *curl;

  FGPRINT("  curl_headers[path=%s]\n", path);

  string resource(urlEncode(service_path + bucket + path));
  string url(host + resource);

  headers_t responseHeaders;
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_NOBODY, true);   // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if(public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("HEAD", "", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
  result = my_curl_easy_perform(curl);
  destroy_curl_handle(curl);

  if(result != 0){
     return result;
  }

  // file exists in s3
  // fixme: clean this up.
  meta.clear();
  for (headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      meta[key] = value;
    }else if(key == "Content-Length"){
      meta[key] = value;
    }else if(key == "ETag"){
      meta[key] = value;
    }else if(key == "Last-Modified"){
      meta[key] = value;
    }else if(key.substr(0, 5) == "x-amz"){
      meta[key] = value;
    }else{
      // Check for upper case
      transform(key.begin(), key.end(), key.begin(), static_cast<int (*)(int)>(std::tolower));
      if(key.substr(0, 5) == "x-amz"){
        meta[key] = value;
      }
    }
  }

  return 0;
}

CURL *create_head_handle(head_data *request_data)
{
  CURL *curl_handle= create_curl_handle();
  string realpath  = get_realpath(request_data->path->c_str());
  string resource  = urlEncode(service_path + bucket + realpath);
  string url       = host + resource;

  // libcurl 7.17 does deep copy of url, deep copy "stable" url
  string my_url = prepare_url(url.c_str());
  request_data->url = new string(my_url.c_str());
  request_data->requestHeaders = 0;
  request_data->responseHeaders = new headers_t;

  curl_easy_setopt(curl_handle, CURLOPT_URL, request_data->url->c_str());
  curl_easy_setopt(curl_handle, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl_handle, CURLOPT_FILETIME, true); // Last-Modified

  // requestHeaders
  string date = get_date();
  request_data->requestHeaders = curl_slist_append(
      request_data->requestHeaders, string("Date: " + date).c_str());
  request_data->requestHeaders = curl_slist_append(
      request_data->requestHeaders, string("Content-Type: ").c_str());
  if(public_bucket.substr(0,1) != "1") {
    request_data->requestHeaders = curl_slist_append(
        request_data->requestHeaders, string("Authorization: AWS " + AWSAccessKeyId + ":" +
          calc_signature("HEAD", "", "", date, request_data->requestHeaders, resource)).c_str());
  }
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, request_data->requestHeaders);

  // responseHeaders
  curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, request_data->responseHeaders);
  curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, header_callback);

  return curl_handle;
}

/**
 * @return fuse return code
 */
int my_curl_easy_perform(CURL* curl, BodyData* body, BodyData* head, FILE* f)
{
  time_t now;

  if(debug){
    char* ptr_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL , &ptr_url);
    SYSLOGDBG("connecting to URL %s", ptr_url ? ptr_url : "unknown");
  }

  // curl_easy_setopt(curl, CURLOPT_VERBOSE, true);
  if(ssl_verify_hostname.substr(0,1) == "0"){
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  }
  if(curl_ca_bundle.size() != 0){
    curl_easy_setopt(curl, CURLOPT_CAINFO, curl_ca_bundle.c_str());
  }
  // set dns cache
  my_set_curl_share(curl);

  long responseCode;

  // 1 attempt + retries...
  int t = retries + 1;
  while (t-- > 0) {
    if (f) {
      rewind(f);
    }
    CURLcode curlCode = curl_easy_perform(curl);

    switch (curlCode) {
      case CURLE_OK:
        // Need to look at the HTTP response code

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode) != 0) {
          SYSLOGERR("curl_easy_getinfo failed while trying to retrieve HTTP response code");
          return -EIO;
        }
        SYSLOGDBG("HTTP response code %ld", responseCode);

        if (responseCode < 400) {
          return 0;
        }
        if (responseCode >= 500) {
          SYSLOGERR("###HTTP response=%ld", responseCode);
          sleep(4);
          break; 
        }

        // Service response codes which are >= 400 && < 500
        switch(responseCode) {
          case 400:
            SYSLOGDBGERR("HTTP response code 400 was returned");
            SYSLOGDBGERR("Body Text: %s", (body ? body->str() : ""));
            SYSLOGDBG("Now returning EIO");
            return -EIO;

          case 403:
            SYSLOGDBGERR("HTTP response code 403 was returned");
            SYSLOGDBGERR("Body Text: %s", (body ? body->str() : ""));
            return -EPERM;

          case 404:
            SYSLOGDBG("HTTP response code 404 was returned");
            SYSLOGDBG("Body Text: %s", (body ? body->str() : ""));
            SYSLOGDBG("Now returning ENOENT");
            return -ENOENT;

          default:
            SYSLOGERR("###response=%ld", responseCode);
            SYSLOGDBG("Body Text: %s", (body ? body->str() : ""));
            FGPRINT("responseCode %ld\n", responseCode);
            FGPRINT("Body Text: %s", (body ? body->str() : ""));
            return -EIO;
        }
        break;

      case CURLE_WRITE_ERROR:
        SYSLOGERR("### CURLE_WRITE_ERROR");
        sleep(2);
        break; 

      case CURLE_OPERATION_TIMEDOUT:
        SYSLOGERR("### CURLE_OPERATION_TIMEDOUT");
        sleep(2);
        break; 

      case CURLE_COULDNT_RESOLVE_HOST:
        SYSLOGERR("### CURLE_COULDNT_RESOLVE_HOST");
        sleep(2);
        break; 

      case CURLE_COULDNT_CONNECT:
        SYSLOGERR("### CURLE_COULDNT_CONNECT");
        sleep(4);
        break; 

      case CURLE_GOT_NOTHING:
        SYSLOGERR("### CURLE_GOT_NOTHING");
        sleep(4);
        break; 

      case CURLE_ABORTED_BY_CALLBACK:
        SYSLOGERR("### CURLE_ABORTED_BY_CALLBACK");
        sleep(4);
        now = time(0);
        curl_times[curl] = now;
        break; 

      case CURLE_PARTIAL_FILE:
        SYSLOGERR("### CURLE_PARTIAL_FILE");
        sleep(4);
        break; 

      case CURLE_SEND_ERROR:
        SYSLOGERR("### CURLE_SEND_ERROR");
        sleep(2);
        break;

      case CURLE_RECV_ERROR:
        SYSLOGERR("### CURLE_RECV_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CACERT:
        // try to locate cert, if successful, then set the
        // option and continue
        if (curl_ca_bundle.size() == 0) {
           locate_bundle();
           if (curl_ca_bundle.size() != 0) {
              t++;
              curl_easy_setopt(curl, CURLOPT_CAINFO, curl_ca_bundle.c_str());
              // break for switch-case, and continue loop.
              break;
           }
        }
        SYSLOGERR("curlCode: %i  msg: %s", curlCode, curl_easy_strerror(curlCode));
        fprintf (stderr, "%s: curlCode: %i -- %s\n", 
           program_name.c_str(),
           curlCode,
           curl_easy_strerror(curlCode));
        exit(EXIT_FAILURE);
        break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
      case CURLE_PEER_FAILED_VERIFICATION:
        first_pos = bucket.find_first_of(".");
        if (first_pos != string::npos) {
          fprintf (stderr, "%s: curl returned a CURL_PEER_FAILED_VERIFICATION error\n", program_name.c_str());
          fprintf (stderr, "%s: security issue found: buckets with periods in their name are incompatible with https\n", program_name.c_str());
          fprintf (stderr, "%s: This check can be over-ridden by using the -o ssl_verify_hostname=0\n", program_name.c_str());
          fprintf (stderr, "%s: The certificate will still be checked but the hostname will not be verified.\n", program_name.c_str());
          fprintf (stderr, "%s: A more secure method would be to use a bucket name without periods.\n", program_name.c_str());
        } else {
          fprintf (stderr, "%s: my_curl_easy_perform: curlCode: %i -- %s\n", 
             program_name.c_str(),
             curlCode,
             curl_easy_strerror(curlCode));
        }
        exit(EXIT_FAILURE);
        break;
#endif

      // This should be invalid since curl option HTTP FAILONERROR is now off
      case CURLE_HTTP_RETURNED_ERROR:
        SYSLOGERR("### CURLE_HTTP_RETURNED_ERROR");

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode) != 0) {
          return -EIO;
        }
        SYSLOGERR("###response=%ld", responseCode);

        // Let's try to retrieve the 

        if (responseCode == 404) {
          return -ENOENT;
        }
        if (responseCode < 500) {
          return -EIO;
        }
        break;

      // Unknown CURL return code
      default:
        SYSLOGERR("###curlCode: %i  msg: %s", curlCode, curl_easy_strerror(curlCode));
        exit(EXIT_FAILURE);
        break;
    }
    if(body){
      body->Clear();
    }
    if(head){
      head->Clear();
    }
    SYSLOGERR("###retrying...");
  }
  SYSLOGERR("###giving up");
  return -EIO;
}

// libcurl callback
size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data)
{
  BodyData* body  = (BodyData*)data;

  if(!body->Append(ptr, blockSize, numBlocks)){
    FGPRINT("WriteMemoryCallback(): BodyData.Append() returned false.\n");
    S3FS_FUSE_EXIT();
    return -1;
  }
  return (blockSize * numBlocks);
}

// read_callback
// http://curl.haxx.se/libcurl/c/post-callback.html
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
 
  if(size*nmemb < 1){
    return 0;
  }
  if(pooh->sizeleft) {
    *(char *)ptr = pooh->readptr[0]; /* copy one single byte */ 
    pooh->readptr++;                 /* advance pointer */ 
    pooh->sizeleft--;                /* less data left */ 
    return 1;                        /* we return 1 byte at a time! */ 
  }
 
  return 0;                          /* no more data left to deliver */ 
}

// homegrown timeout mechanism
int my_curl_progress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
  CURL* curl = static_cast<CURL*>(clientp);

  time_t now = time(0);
  progress_t p(dlnow, ulnow);

  pthread_mutex_lock(&curl_handles_lock);

  // any progress?
  if(p != curl_progress[curl]) {
    // yes!
    curl_times[curl] = now;
    curl_progress[curl] = p;
  } else {
    // timeout?
    if (now - curl_times[curl] > readwrite_timeout) {
      pthread_mutex_unlock( &curl_handles_lock );

      SYSLOGERR("timeout  now: %li  curl_times[curl]: %lil  readwrite_timeout: %li",
                      (long int)now, curl_times[curl], (long int)readwrite_timeout);

      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  pthread_mutex_unlock(&curl_handles_lock);
  return 0;
}

/**
 * Returns the Amazon AWS signature for the given parameters.
 *
 * @param method e.g., "GET"
 * @param content_type e.g., "application/x-directory"
 * @param date e.g., get_date()
 * @param resource e.g., "/pub"
 */
string calc_signature(string method, string strMD5, string content_type, string date, curl_slist* headers, string resource)
{
  int ret;
  int bytes_written;
  int offset;
  int write_attempts = 0;

  string Signature;
  string StringToSign;
  StringToSign += method + "\n";
  StringToSign += strMD5 + "\n"; // md5
  StringToSign += content_type + "\n";
  StringToSign += date + "\n";
  int count = 0;
  if(headers != 0) {
    do {
      if(strncmp(headers->data, "x-amz", 5) == 0) {
        ++count;
        StringToSign += headers->data;
        StringToSign += 10; // linefeed
      }
    } while ((headers = headers->next) != 0);
  }

  StringToSign += resource;

  const void* key = AWSSecretAccessKey.data();
  int key_len = AWSSecretAccessKey.size();
  const unsigned char* d = reinterpret_cast<const unsigned char*>(StringToSign.data());
  int n = StringToSign.size();
  unsigned int md_len;
  unsigned char md[EVP_MAX_MD_SIZE];

  HMAC(evp_md, key, key_len, d, n, md, &md_len);

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  offset = 0;
  for(;;) {
    bytes_written = BIO_write(b64, &(md[offset]), md_len);
    write_attempts++;
    // -1 indicates that an error occurred, or a temporary error, such as
    // the server is busy, occurred and we need to retry later.
    // BIO_write can do a short write, this code addresses this condition
    if(bytes_written <= 0) {
      // Indicates whether a temporary error occurred or a failure to
      // complete the operation occurred
      if ((ret = BIO_should_retry(b64))) {
        // Wait until the write can be accomplished
        if(write_attempts <= 10)
          continue;

        // Too many write attempts
        SYSLOGERR("Failure during BIO_write, returning null String");  
        BIO_free_all(b64);
        Signature.clear();
        return Signature;
      } else {
        // If not a retry then it is an error
        SYSLOGERR("Failure during BIO_write, returning null String");  
        BIO_free_all(b64);
        Signature.clear();
        return Signature;
      }
    }
  
    // The write request succeeded in writing some Bytes
    offset += bytes_written;
    md_len -= bytes_written;
  
    // If there is no more data to write, the request sending has been
    // completed
    if(md_len <= 0){
      break;
    }
  }

  // Flush the data
  ret = BIO_flush(b64);
  if ( ret <= 0) { 
    SYSLOGERR("Failure during BIO_flush, returning null String");  
    BIO_free_all(b64);
    Signature.clear();
    return Signature;
  } 

  BUF_MEM *bptr;

  BIO_get_mem_ptr(b64, &bptr);

  Signature.resize(bptr->length - 1);
  memcpy(&Signature[0], bptr->data, bptr->length-1);

  BIO_free_all(b64);

  return Signature;
}

void locate_bundle(void)
{
  // See if environment variable CURL_CA_BUNDLE is set
  // if so, check it, if it is a good path, then set the
  // curl_ca_bundle variable to it
  char *CURL_CA_BUNDLE; 

  if(curl_ca_bundle.size() == 0) {
    CURL_CA_BUNDLE = getenv("CURL_CA_BUNDLE");
    if(CURL_CA_BUNDLE != NULL)  {
      // check for existance and readability of the file
      ifstream BF(CURL_CA_BUNDLE);
      if(BF.good()) {
         BF.close();
         curl_ca_bundle.assign(CURL_CA_BUNDLE); 
      } else {
        fprintf(stderr, "%s: file specified by CURL_CA_BUNDLE environment variable is not readable\n",
                program_name.c_str());
        exit(EXIT_FAILURE);
      }
      return;
    }
  }

  // not set via environment variable, look in likely locations

  ///////////////////////////////////////////
  // from curl's (7.21.2) acinclude.m4 file
  ///////////////////////////////////////////
  // dnl CURL_CHECK_CA_BUNDLE
  // dnl -------------------------------------------------
  // dnl Check if a default ca-bundle should be used
  // dnl
  // dnl regarding the paths this will scan:
  // dnl /etc/ssl/certs/ca-certificates.crt Debian systems
  // dnl /etc/pki/tls/certs/ca-bundle.crt Redhat and Mandriva
  // dnl /usr/share/ssl/certs/ca-bundle.crt old(er) Redhat
  // dnl /usr/local/share/certs/ca-root.crt FreeBSD
  // dnl /etc/ssl/cert.pem OpenBSD
  // dnl /etc/ssl/certs/ (ca path) SUSE
  ifstream BF("/etc/pki/tls/certs/ca-bundle.crt"); 
  if(BF.good()) {
     BF.close();
     curl_ca_bundle.assign("/etc/pki/tls/certs/ca-bundle.crt"); 
     return;
  }

  return;
}

string GetContentMD5(int fd)
{
  BIO*     b64;
  BIO*     bmem;
  BUF_MEM* bptr;
  string   Signature;
  unsigned char* md5hex;

  if(NULL == (md5hex = md5hexsum(fd))){
    return string("");
  }

  b64  = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64  = BIO_push(b64, bmem);

  BIO_write(b64, md5hex, MD5_DIGEST_LENGTH);
  free(md5hex);
  if(1 != BIO_flush(b64)){
    BIO_free_all(b64);
    return string("");
  }
  BIO_get_mem_ptr(b64, &bptr);

  Signature.resize(bptr->length - 1);
  memcpy(&Signature[0], bptr->data, bptr->length - 1);

  BIO_free_all(b64);

  return Signature;
}

unsigned char* md5hexsum(int fd)
{
  MD5_CTX c;
  char    buf[512];
  ssize_t bytes;
  unsigned char* result = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

  // seek to top of file.
  if(-1 == lseek(fd, 0, SEEK_SET)){
    return NULL;
  }

  memset(buf, 0, 512);
  MD5_Init(&c);
  while((bytes = read(fd, buf, 512)) > 0) {
    MD5_Update(&c, buf, bytes);
    memset(buf, 0, 512);
  }
  MD5_Final(result, &c);

  if(-1 == lseek(fd, 0, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

string md5sum(int fd)
{
  char md5[2 * MD5_DIGEST_LENGTH + 1];
  char hexbuf[3];
  unsigned char* md5hex;

  if(NULL == (md5hex = md5hexsum(fd))){
    return string("");
  }

  memset(md5, 0, 2 * MD5_DIGEST_LENGTH + 1);
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    snprintf(hexbuf, 3, "%02x", md5hex[i]);
    strncat(md5, hexbuf, 2);
  }
  free(md5hex);

  return string(md5);
}

bool InitMimeType(const char* file)
{
  if(!file){
    return false;
  }

  string line;
  ifstream MT(file);
  if (MT.good()) {
    while (getline(MT, line)) {
      if(line[0]=='#'){
        continue;
      }
      if(line.size() == 0){
        continue;
      }

      stringstream tmp(line);
      string mimeType;
      tmp >> mimeType;
      while (tmp) {
        string ext;
        tmp >> ext;
        if (ext.size() == 0){
          continue;
        }
        mimeTypes[ext] = mimeType;
      }
    }
  }
  return true;
}

/**
 * @param s e.g., "index.html"
 * @return e.g., "text/html"
 */
string lookupMimeType(string s)
{
  string result("application/octet-stream");
  string::size_type last_pos = s.find_last_of('.');
  string::size_type first_pos = s.find_first_of('.');
  string prefix, ext, ext2;

  // No dots in name, just return
  if(last_pos == string::npos){
    return result;
  }
  // extract the last extension
  if(last_pos != string::npos){
    ext = s.substr(1+last_pos, string::npos);
  }
  if (last_pos != string::npos) {
     // one dot was found, now look for another
     if (first_pos != string::npos && first_pos < last_pos) {
        prefix = s.substr(0, last_pos);
        // Now get the second to last file extension
        string::size_type next_pos = prefix.find_last_of('.');
        if (next_pos != string::npos) {
           ext2 = prefix.substr(1+next_pos, string::npos);
        }
     }
  }

  // if we get here, then we have an extension (ext)
  mimes_t::const_iterator iter = mimeTypes.find(ext);
  // if the last extension matches a mimeType, then return
  // that mime type
  if (iter != mimeTypes.end()) {
    result = (*iter).second;
    return result;
  }

  // return with the default result if there isn't a second extension
  if(first_pos == last_pos){
     return result;
  }

  // Didn't find a mime-type for the first extension
  // Look for second extension in mimeTypes, return if found
  iter = mimeTypes.find(ext2);
  if (iter != mimeTypes.end()) {
     result = (*iter).second;
     return result;
  }

  // neither the last extension nor the second-to-last extension
  // matched a mimeType, return the default mime type 
  return result;
}

