// tau5_discovery.cpp - Main NIF file with dirty scheduling
#include "erl_nif.h"
#include "tau5_discovery_interface.h"
#include <string>
#include <mutex>
#include <atomic>
#include <iostream>

// Notification system
struct NotificationContext {
  std::mutex notification_mutex;
  ErlNifPid notification_pid;
  std::atomic<bool> has_notification_pid{false};
};

static NotificationContext notification_ctx;
static std::mutex discovery_mutex;

// FIXED: Proper thread callback with fresh env
void on_peers_changed() {
  std::lock_guard<std::mutex> lock(discovery_mutex);

  if (!notification_ctx.has_notification_pid.load()) {
    return;
  }

  // CRITICAL: Always create fresh env for thread callbacks
  ErlNifEnv *msg_env = enif_alloc_env();
  if (!msg_env) {
    return;
  }

  ERL_NIF_TERM peer_list = list_peers_impl(msg_env);
  ERL_NIF_TERM message = enif_make_tuple2(
      msg_env,
      enif_make_atom(msg_env, "peers_changed"),
      peer_list);

  {
    std::lock_guard<std::mutex> notif_lock(notification_ctx.notification_mutex);
    if (notification_ctx.has_notification_pid.load()) {
      // Send from NULL env (thread context)
      int result = enif_send(nullptr, &notification_ctx.notification_pid, msg_env, message);
      if (result == 0) {
        notification_ctx.has_notification_pid.store(false);
      }
    }
  }

  // CRITICAL: Always free the env immediately
  enif_free_env(msg_env);
}

bool notifications_enabled() {
  return notification_ctx.has_notification_pid.load();
}

// STEP 1: Add back mutex and implementation call with proper logging
static ERL_NIF_TERM start_discovery_dirty(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  std::string info_string;

  // Try string first (simpler)
  char buffer[1024];
  if (enif_get_string(env, argv[0], buffer, sizeof(buffer), ERL_NIF_LATIN1) > 0) {
    info_string = buffer;
  } else {
    // Try binary
    ErlNifBinary bin;
    if (enif_inspect_binary(env, argv[0], &bin)) {
      info_string.assign(reinterpret_cast<const char*>(bin.data), bin.size);
    } else {
      return enif_make_badarg(env);
    }
  }

  // Add back mutex
  std::lock_guard<std::mutex> lock(discovery_mutex);

  // Add back implementation call with exception handling
  try {
    start_discovery_impl(info_string.c_str());
  } catch (const std::exception& e) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                           enif_make_string(env, e.what(), ERL_NIF_LATIN1));
  } catch (...) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                           enif_make_string(env, "unknown_exception", ERL_NIF_LATIN1));
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM stop_discovery(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  std::lock_guard<std::mutex> lock(discovery_mutex);
  stop_discovery_impl();

  {
    std::lock_guard<std::mutex> notif_lock(notification_ctx.notification_mutex);
    notification_ctx.has_notification_pid.store(false);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM list_peers(ErlNifEnv *env, int argc, const ERL_NIF_TERM[]) {
  std::lock_guard<std::mutex> lock(discovery_mutex);
  return list_peers_impl(env);
}

static ERL_NIF_TERM set_notification_pid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  std::lock_guard<std::mutex> lock(notification_ctx.notification_mutex);

  if (!enif_self(env, &notification_ctx.notification_pid)) {
    return enif_make_badarg(env);
  }

  notification_ctx.has_notification_pid.store(true);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM clear_notification_pid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  std::lock_guard<std::mutex> lock(notification_ctx.notification_mutex);
  notification_ctx.has_notification_pid.store(false);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM enable_nif_logging(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  enable_nif_logging_impl();
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM disable_nif_logging(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  disable_nif_logging_impl();
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM is_nif_logging_enabled(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  bool enabled = is_nif_logging_enabled_impl();
  return enif_make_atom(env, enabled ? "true" : "false");
}

// PRODUCTION READY: Clean function table with dirty scheduler
static ErlNifFunc nif_funcs[] = {
    // name, arity, function, flags
    {"start", 1, start_discovery_dirty, ERL_NIF_DIRTY_JOB_IO_BOUND},  // RESTORED: Dirty scheduler for heavy I/O
    {"stop", 0, stop_discovery, 0},
    {"list", 0, list_peers, 0},
    {"set_notification_pid", 0, set_notification_pid, 0},
    {"clear_notification_pid", 0, clear_notification_pid, 0},
    {"enable_nif_logging", 0, enable_nif_logging, 0},
    {"disable_nif_logging", 0, disable_nif_logging, 0},
    {"is_nif_logging_enabled", 0, is_nif_logging_enabled, 0}
};

ERL_NIF_INIT(tau5_discovery, nif_funcs, NULL, NULL, NULL, NULL)