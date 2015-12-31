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
 *  along with DroidTracer. If not, see
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

/* kernel header */
#include <linux/rbtree.h>
#include <linux/genetlink.h>
#include <jni.h>

/* libnl header */
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

/* c++ stl */
#include <map>
#include <string>

#include <genl-endpoint.h>

#define  LOG_TAG    "RV; droidtracer.cpp"

#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* add this line, to avoiding writing 'std::' every time a string (or
   any other container) is declared */  
using namespace std; 

#ifdef __cplusplus
extern "C" {
#endif
	
	/* cached refs for later callbacks */
	JavaVM *g_vm;
	jobject g_obj;
	map<string, jmethodID> g_mids;
	struct nl_sock *sock;
	int family = -1;
	struct nla_policy policy[ATTR_MAX + 1];
	//int tmp_array_len = 120;
	//jbyte *tmp_array = new jbyte[tmp_array_len];

	/*
	 * callback method, which is triggered from kernel module on
	 * new events.
	 */
	static int on_netlink_event(struct nl_msg *msg, void *arg)
	{
		struct nlmsghdr *nlh = nlmsg_hdr(msg);
		struct nlattr *attrs[ATTR_MAX+1];
		JNIEnv *g_env;
		int err;

		// Validate message and parse attributes
		err = genlmsg_parse(nlh, 0, attrs, ATTR_MAX, policy);
		if (err)
			LOGE("wrong netlink header");
		
		err = g_vm->GetEnv((void **) &g_env, JNI_VERSION_1_6);
		if (err) {
			if (err == JNI_EDETACHED) {
				if (g_vm->AttachCurrentThread(&g_env, NULL)) {
					LOGE("failed to attach thread");
					return -1;
				}
			} else if (err == JNI_EVERSION) {
				LOGE("version not supported");
				return -1;
			}
		}
		
		if (attrs[CODE] && attrs[PARCEL] && attrs[UID] && attrs[TIME]) {      
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
			  // put whatever logic you want to populate the values here.
			  tmp_array[j] = *((uint8_t *) nla_data(attrs[PARCEL])+j); 
			  }
			  g_env->SetByteArrayRegion(bArray, 0, len, tmp_array);      
			*/

			// a Java reference that holds a pointer to the c++ buffer */
			jobject bArray = g_env->NewDirectByteBuffer(nla_data(attrs[PARCEL]), nla_len(attrs[PARCEL]));

			jstring syscall = NULL;
			/* for other syscalls (except Binder) */			
			if(attrs[SERVICE])
				syscall = g_env->NewStringUTF(nla_get_string(attrs[SERVICE]));

			/* execute java-callback method */
			g_env->CallVoidMethod(g_obj, g_mids["onNetlink"], syscall,
					      (jint) nla_get_u32(attrs[UID]),
					      (jint) nla_get_u32(attrs[TIME]),
					      (jint) nla_get_u8(attrs[CODE]), 
					      bArray, (jlong)  nlh->nlmsg_seq);          	

			if(attrs[SERVICE])				
				g_env->DeleteLocalRef(syscall);
			
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

	static jboolean genl_send_int(uint8_t cmd, int value) {
		struct nl_msg *msg;
		struct my_hdr *msg_hdr;
		
		if(!sock || family < 0) 
			return JNI_FALSE;  
		
		/* allocate memory for message 
		   (incl. space for header) */
		msg = nlmsg_alloc();
		if(!msg)
			return JNI_FALSE;
		
		/* add generic nl headers to netlink message */
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
			    family, 0, NLM_F_ECHO, cmd, VERSION_NR);
		
		/* jint is 'signed 32 bits' */
		nla_put_u32(msg, UID, (uint32_t) value);
		
		nl_send_auto(sock, msg);
		nlmsg_free(msg);
		
		return JNI_TRUE;
	}

	static jboolean genl_send_str(uint8_t cmd, jstring value, JNIEnv *env) {
		struct nl_msg *msg;
		
		if(!sock || family < 0) 
			return JNI_FALSE;  
		
		msg = nlmsg_alloc();
		if(!msg)
			return JNI_FALSE;
		
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
			    family, 0, NLM_F_ECHO, cmd, VERSION_NR);
		
		const char *c_service = env->GetStringUTFChars(value, 0);  
		nla_put_string(msg, SERVICE, c_service);
		
		nl_send_auto(sock, msg);
		nlmsg_free(msg);   
		env->ReleaseStringUTFChars(value, c_service);
		
		return JNI_TRUE;
	}

	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_startInterceptingApp(JNIEnv *env,
														jobject thiz,
														jint uid)
	{
		return genl_send_int(TRACE_APP, uid);
	}	
	
	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_stopInterceptingApp(JNIEnv *env,
													       jobject thiz,
													       jint uid)
	{
		return genl_send_int(UNTRACE_APP, uid);
	}

	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_setDroidTracerUid(JNIEnv *env,
													     jobject thiz,
													     jint uid)
	{
		return genl_send_int(SET_DROIDTRACER_UID, uid);
	}
	
	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_setLowestUidTraced(JNIEnv *env,
													      jobject thiz,
													      jint uid)
	{
		return genl_send_int(SET_LOWEST_UID_TRACED, uid);
	}
	
	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_addServiceToBlacklist(JNIEnv *env,
														 jobject thiz,
														 jstring service)
	{
		return genl_send_str(BLACKLIST_INTERFACE, service, env);
	}

	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_addServiceToWhitelist(JNIEnv *env,
														 jobject thiz,
														 jstring service)
	{
		return genl_send_str(WHITELIST_INTERFACE, service, env);
	}

	/*
	 * Register Java callback method that can be invoked from C++.
	 * E.g., used to connect "onNetlinkEvent" in Java with "on_netlink_event"
	 */
	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_registerCallback(JNIEnv *env,
													    jobject obj,
													    jstring method,
													    jstring methodSignature)
	{
		env->GetJavaVM(&g_vm);
		
		/* convert local to global reference 
		   (local will die after this method call) */
		g_obj = env->NewGlobalRef(obj);
		
		// save refs for callback
		jclass g_clazz = env->GetObjectClass(g_obj);
		jclass g_superclazz = env->GetSuperclass(g_clazz);
		
		if (!g_superclazz) {
			LOGE("class not found");
			return JNI_FALSE;
		}  

		/* convert and assign Java String to C-String 
		   TODO use NewString, GetStringLength, GetStringChars? */
		const char *c_method = env->GetStringUTFChars(method, 0);
		const char *c_methodSignature = env->GetStringUTFChars(methodSignature, 0);
		jint c_method_len = env->GetStringUTFLength(method);

		g_mids[string(c_method, c_method_len)] = env->GetMethodID(g_superclazz,
									  c_method, c_methodSignature);
		
		if (!g_mids[string(c_method, c_method_len)]) {    
			LOGE("method not found: %s", c_method);
			return JNI_FALSE;
		}
		env->ReleaseStringUTFChars(method, c_method);
		env->ReleaseStringUTFChars(methodSignature, c_methodSignature);    

		return JNI_TRUE;
	}
	
	JNIEXPORT jboolean JNICALL Java_org_multics_kuester_droidtracer_DroidTracerService_initNetlink(JNIEnv* env,
												       jobject thiz)
	{
		int err;
		
		policy[TIME].type = NLA_U32;
		policy[CODE].type = NLA_U8;
		policy[PARCEL].type = NLA_UNSPEC;
		policy[UID].type = NLA_U32;
		policy[SERVICE].type = NLA_STRING;

		sock = nl_socket_alloc();
		if(!sock) {
			LOGE("cannot allocate netlink socket");
			return JNI_FALSE;
		}

		/*
		  TODO can we increase msg_buf_size?

		  int msg_buf_size = nl_socket_set_msg_buf_size(sock, 1000000);
		  size_t bla = nl_socket_get_msg_buf_size(sock);
		  LOGD("%zu", bla);
		*/
		
		/* connect to kernel side */
		err = genl_connect(sock);
		if(err) {
			LOGE("genl_connect failed: %s", nl_geterror(err));
			return JNI_FALSE;
		}
		
		/* ask kernel to resolve family name to family id */
		family = genl_ctrl_resolve(sock, FAMILY_NAME);
		if(family < 0) {
			LOGE("cannot resolve nl family name: %s", FAMILY_NAME);
			return JNI_FALSE;
		}
		/* Prepare socket to receive message from kernel by
		 * specifying callback function on_netlink_event()
		 * TODO NL_CB_MSG_IN?
		 */
		err = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
					  on_netlink_event, NULL);
		if(err) 
			return JNI_FALSE;
		
		nl_socket_disable_seq_check(sock);
		
		LOGI("netlink initialised, start receiving messages");

		/*
		 * Start receiving messages. The function
		 * nl_recvmsgs_default() will block (no polling) until
		 * one or more netlink messages are received
		 */	
		while(1) {
			if(int err = nl_recvmsgs_default(sock)) 
				LOGE("failed to receive message: %d", err);
		}
	}
	
#ifdef __cplusplus
}
#endif
