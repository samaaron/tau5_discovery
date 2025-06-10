#pragma once

#include "erl_nif.h"

// Implementation functions (defined in tau5_discovery_impl.cpp)
void start_discovery_impl(const char* info_string);
void stop_discovery_impl();
ERL_NIF_TERM list_peers_impl(ErlNifEnv *env);

// Logging control functions
void enable_nif_logging_impl();
void disable_nif_logging_impl();
bool is_nif_logging_enabled_impl();

// Notification functions (defined in tau5_discovery_impl.cpp)
void on_peers_changed();
bool notifications_enabled();