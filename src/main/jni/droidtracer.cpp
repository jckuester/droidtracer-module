/*********************************************************************
 *  This is part of DroidTracer
 *  (http://kuester.multics.org/DroidTracer).
 *
 *  Copyright (c) 2013-2015 by Jan-Christoph Küster
 *  <jckuester@gmail.com>
 *
 *  DroidTracer is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  DroidTracer is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with DroidTracer.  If not, see
 *  <http://www.gnu.org/licenses/>.
 ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <android/log.h>

#include <linux/genetlink.h>
#include <jni.h>

/* libnl header */
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

/* c++ stl */
#include <map>
#include <string>

#include <comm_netlink.h>

/* reverse engineered internal android */
//#include "binder/Parcel.h"
//#include "utils/Unicode.h"
// link to shared lib on android (hidden)
//#include <binder/Parcel.h>
//#include <utils/Unicode.h>

#define  LOG_TAG    "RV; droidtracer.cpp"

#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
//#define  LOGD(...) __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, const char *fmt, va_list ap)
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* add this line, to avoiding writing 'std::' every time a string (or any  
other container) is declared.*/  
using namespace std; 
//using namespace android;

#ifdef __cplusplus
extern "C" {
#endif

  // cached refs for later callbacks  
  JavaVM *g_vm;
  jobject g_obj;
  map<string, jmethodID> g_mids;
  struct nl_sock *sock;
  int family = -1;
  struct nla_policy policy[ATTR_MAX + 1];
  int tmp_array_len = 120;
  jbyte *tmp_array = new jbyte[tmp_array_len];

  JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_startInterceptingApp(JNIEnv *env,
											  jobject thiz, jint uid)
  {
    struct nl_msg *msg;

    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
  
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    // jint is 'signed 32 bits'
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		ADD_APP, VERSION_NR);
  
    nla_put_u32(msg, UID, (uint32_t) uid);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   

    return JNI_TRUE;
  }



  JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_stopInterceptingApp(JNIEnv *env,
											  jobject thiz, jint uid)
  {
    struct nl_msg *msg;

    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
    
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		DELETE_APP, VERSION_NR);
  
    // jint is 'signed 32 bits'
    nla_put_u32(msg, UID, (uint32_t) uid);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   

    return JNI_TRUE;
  }
  
  JNIEXPORT jboolean JNICALL  Java_org_multics_kuester_droidtracer_DroidTracerService_addServiceToBlacklist(JNIEnv *env,
											    jobject thiz, jstring service)
  {
    struct nl_msg *msg;
    
    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
  
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    // jint is 'signed 32 bits'
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		ADD_SERVICE_BLACKLIST, VERSION_NR);

    const char *c_service = env->GetStringUTFChars(service, 0);  
    nla_put_string(msg, SERVICE, c_service);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   
    env->ReleaseStringUTFChars(service, c_service);

    return JNI_TRUE;
  }

  JNIEXPORT jboolean JNICALL  Java_org_multics_kuester_droidtracer_DroidTracerService_addServiceToWhitelist(JNIEnv *env,
											    jobject thiz, jstring service)
  {
    struct nl_msg *msg;
    
    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
  
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    // jint is 'signed 32 bits'
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		ADD_SERVICE_WHITELIST, VERSION_NR);

    const char *c_service = env->GetStringUTFChars(service, 0);  
    nla_put_string(msg, SERVICE, c_service);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   
    env->ReleaseStringUTFChars(service, c_service);

    return JNI_TRUE;
  }

 JNIEXPORT jboolean JNICALL  Java_org_multics_kuester_droidtracer_DroidTracerService_setDroidTracerUid(JNIEnv *env,
										   jobject thiz, jint droidTracerUid)
  {
    struct nl_msg *msg;

    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
  
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		SET_DROIDTRACER_UID, VERSION_NR);

    // jint is 'signed 32 bits'
    nla_put_u32(msg, UID, (uint32_t) droidTracerUid);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   

    return JNI_TRUE;
  }

 JNIEXPORT jboolean JNICALL  Java_org_multics_kuester_droidtracer_DroidTracerService_interceptAllApps(JNIEnv *env,
										   jobject thiz, jint droidTracerUid)
  {
    struct nl_msg *msg;

    if(sock == NULL) {
      LOGE("netlink socket not allocated.");
      return JNI_FALSE;
    }
  
    if(family == -1) {
      LOGE("netlink family not found.");
      return JNI_FALSE;
    }
  
    // Construct a generic netlink by allocating a new message, fill in
    // the header and append a simple integer attribute.
    msg = nlmsg_alloc();
  
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
		INTERCEPT_ALL_APPS, VERSION_NR);

    // jint is 'signed 32 bits'
    nla_put_u32(msg, UID, (uint32_t) droidTracerUid);
  
    // Send message over netlink socket
    nl_send_auto(sock, msg);
  
    // Free message
    nlmsg_free(msg);   

    return JNI_TRUE;
  }

  JNIEXPORT void JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_receiveNetlinkEvents(JNIEnv *env,
										      jobject obj)
  {
    if(sock == NULL)
      LOGE("netlink socket not allocated.");
    
    /* wait for new events (no polling, but blocks) */
    while(1) {
      if(int error_code = nl_recvmsgs_default(sock)) 
	LOGE("receiving message failed, error_code=%d", error_code);
    }
  }

  /*
   * Register Java callback method that can be invoked from C++.
   * E.g., used to connect "onNetlinkEvent" in Java with "on_netlink_event"
   */
  JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_registerCallback(JNIEnv *env,
										     jobject obj, jstring method, jstring methodSignature)
  {
    env->GetJavaVM(&g_vm);

    /* convert local to global reference 
       (local will die after this method call) */
    g_obj = env->NewGlobalRef(obj);
  
      // save refs for callback
    jclass g_clazz = env->GetObjectClass(g_obj);
    jclass g_superclazz = env->GetSuperclass(g_clazz);
	
    if (g_superclazz == NULL) {
      LOGE("Error: class not found.");
      return JNI_FALSE;
    }  
    /* Java String in C-String konvertieren und an C-Variable
     zuweisen: */

      // TODO Programs should use the NewString, GetStringLength, GetStringChars
    const char *c_method = env->GetStringUTFChars(method, 0);
    const char *c_methodSignature = env->GetStringUTFChars(methodSignature, 0);
    jint c_method_len = env->GetStringUTFLength(method);

      //g_mid = env->GetMethodID(g_clazz, "callbackEvent", "(Ljava/lang/String;IIILjava/lang/String;)V");
    g_mids[string(c_method, c_method_len)] = env->GetMethodID(g_superclazz, c_method, c_methodSignature);
    
    if (g_mids[string(c_method, c_method_len)] == NULL) {    
      LOGE("Error: method not found: %s", c_method);
      return JNI_FALSE;
    }

    //LOGD("Callback registered: %s(%s)", *c_method, *c_methodSignature);

    // Don't forget this!
    env->ReleaseStringUTFChars(method, c_method);
    env->ReleaseStringUTFChars(methodSignature, c_methodSignature);    

    return JNI_TRUE;
  }
  
  /*
   * gen netlink callback methods. Triggered from kernel module on new events.
   */
  static int on_netlink_event(struct nl_msg *msg, void *arg)
  {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[ATTR_MAX+1];
    JNIEnv *g_env;

    // Validate message and parse attributes
    if(genlmsg_parse(nlh, 0, attrs, ATTR_MAX, policy))
      LOGE("wrong netlink header.");
    
    int getEnvStat = g_vm->GetEnv((void **)&g_env, JNI_VERSION_1_6);
    
    // double check it's all ok
    if (getEnvStat == JNI_EDETACHED) {
      if (g_vm->AttachCurrentThread(&g_env, NULL) != 0) {
	LOGE("failed to attach thread.");
      }
    } else if (getEnvStat == JNI_OK) {
      //LOGD("JNI_OK=%d", JNI_OK);
    } else if (getEnvStat == JNI_EVERSION) {
      LOGE("version not supported.");
    }      

    if (attrs[CODE] && attrs[PARCEL] && attrs[UID] && attrs[TIME]) {      
      //LOGD("%s", nla_get_string(attrs[SERVICE]));	   

      /*
      int len = nla_len(attrs[PARCEL]);
  
      // create java byte array from DATA
      jbyteArray bArray = g_env->NewByteArray(len);
      if (bArray == NULL) {
	return NULL; // out of memory error thrown 
      }
      int j;

      // fill a temp structure to use to populate the java int array
      if(len > tmp_array_len) {
	tmp_array_len = len;	
	tmp_array = new jbyte[len];
      }	
      for (j = 0; j < len; j++) {
	tmp_array[j] = *((uint8_t *) nla_data(attrs[PARCEL])+j); // put whatever logic you want to populate the values here.
      }
      g_env->SetByteArrayRegion(bArray, 0, len, tmp_array);      
      */
      // return a reference of a (Java) object that holds a pointer to the c++ buffer
      jobject bArray = g_env->NewDirectByteBuffer(nla_data(attrs[PARCEL]), nla_len(attrs[PARCEL]));

      // print raw DATA
      //int i=0;
      //for(; i<parcel->dataSize(); i++) {
      //  LOGD("%d", *((uint8_t *) nla_data(attrs[PARCEL])+i));	    
      //}

      // print DATA length
      //uint8_t *data = (uint8_t *) nla_data(attrs[PARCEL]);
      //	  int data_len = nla_len(attrs[PARCEL]);
      //LOGD("data_len: %d", data_len);

      // Convert the C-string (char*) into JNI String (jstring)
      //jstring params = g_env->NewStringUTF(nla_get_string(attrs[PARAMS]));
      //g_env->DeleteLocalRef(params);

      if(attrs[SERVICE]) { 
	/*
	 * for syscalls (not Binder).
	 */
	
	// Convert the C-string (char*) into JNI String (jstring)
	jstring syscall = g_env->NewStringUTF(nla_get_string(attrs[SERVICE]));

	/* execute java-callback method */
	g_env->CallVoidMethod(g_obj, g_mids["onNetlink"], syscall, (jint) nla_get_u32(attrs[UID]), (jint) nla_get_u32(attrs[TIME]), (jint) nla_get_u8(attrs[CODE]), 
			      bArray, (jlong)  nlh->nlmsg_seq);          	

	g_env->DeleteLocalRef(syscall);
      } else {
	/*
	 * for Binder calls.
	 * callback Java method with the same name if a new event occurs
	 */

	/* execute java-callback method */
	g_env->CallVoidMethod(g_obj, g_mids["onNetlink"], NULL, (jint) nla_get_u32(attrs[UID]), (jint) nla_get_u32(attrs[TIME]), (jint) nla_get_u8(attrs[CODE]), 
			      bArray, (jlong) nlh->nlmsg_seq);          	
      }
      
      // only needed if getByteArrayElements was called
      //g_env->ReleaseByteArrayElements(bArray, fill, 0);
      g_env->DeleteLocalRef(bArray);         
      /*
      if (g_env->ExceptionCheck()) {
	g_env->ExceptionDescribe();
      }
      
      g_vm->DetachCurrentThread();
      */
    }
    return 0;
  }
 
  JNIEXPORT void JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_initNetlink(JNIEnv* env,
									       jobject thiz)
  {
    /* attribute policy: defines which attribute has which type (e.g int, char * etc)
     * possible values defined in net/netlink.h
     */
    policy[TIME].type = NLA_U32;
    policy[CODE].type = NLA_U8;
    policy[PARCEL].type = NLA_UNSPEC;
    policy[UID].type = NLA_U32;
    policy[SERVICE].type = NLA_STRING;

    // Allocate a new netlink socket
    sock = nl_socket_alloc();
    if(sock == NULL) {
      LOGE("Could not allocate netlink socket.");
      return;
    }

    /*
    int msg_buf_size = nl_socket_set_msg_buf_size(sock, 1000000000);
    if(msg_buf_size != 0){
      LOGE("Wrong message buffer size.\n");
      return;
    }

    size_t bla = nl_socket_get_msg_buf_size(sock);
    LOGD("%zu", bla);
    LOGD("%zu", SIZE_MAX);
    */

    // Connect to generic netlink socket on kernel side
    if(int error_code = genl_connect(sock)) {
      LOGE("genl_connect failed, error_code=%d, error_msg=%s", error_code, nl_geterror(error_code));
      return;
    }

    // Ask kernel to resolve family name to family id
    family = genl_ctrl_resolve(sock, "DROIDTRACER");
    if(family < 0) {
      LOGE("Could not resolve netlink family name.");
      return;
    }
    // Prepare socket to receive the answer by specifying the callback
    // function to be called for valid messages.
    //nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, on_netlink_event, NULL);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, on_netlink_event, NULL);

    nl_socket_disable_seq_check(sock);

    /*
     * Start receiving messages. The function nl_recvmsgs_default() will block
     * until one or more netlink messages (notification) are received which
     * will be passed on to my_func().
     */

    LOGD("Netlink initialised.");
  }

#ifdef __cplusplus
}
#endif


