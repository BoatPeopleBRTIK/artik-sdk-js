/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#ifndef ADDON_NETWORK_NETWORK_H_
#define ADDON_NETWORK_NETWORK_H_

#include <node.h>
#include <node_object_wrap.h>

#include <uv.h>
#include <artik_network.hh>
#include <utils.h>

namespace artik {

class NetworkWrapper : public node::ObjectWrap {
 public:
  static void Init(v8::Local<v8::Object> exports);

  Network* getObj() { return m_network; }
  v8::Persistent<v8::Function>* getWatchOnlineStatusCb() {
    return m_watch_online_status_cb;
  }

 private:
  explicit NetworkWrapper(v8::Persistent<v8::Function> *callback,
                          bool enable_watch_online_status = false);
  ~NetworkWrapper();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static v8::Persistent<v8::Function> constructor;

  static void set_network_config(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void get_network_config(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void get_current_public_ip(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void dhcp_client_start(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void dhcp_client_stop(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void dhcp_server_start(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void dhcp_server_stop(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void get_online_status(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  Network* m_network;
  v8::Persistent<v8::Function>* m_watch_online_status_cb;
  watch_online_status_handle m_handle;
};

}  // namespace artik


#endif  // ADDON_NETWORK_NETWORK_H_
