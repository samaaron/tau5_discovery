#include "tau5_discovery_interface.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <iostream>
#include <sstream>
#include <random>
#include <cstring>
#include <condition_variable>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <regex>
#include <fstream>

// ASIO for IPv6 scope filtering only
#include <asio.hpp>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#include <BaseTsd.h>   // brings in SSIZE_T
typedef SSIZE_T ssize_t;
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/wireless.h>
#endif
#ifdef __APPLE__
#include <sys/ioctl.h>
#include <net/if_media.h>
#endif
typedef int socket_t;
#define INVALID_SOCKET_VALUE -1
#define close_socket close
#endif

// Cross-platform setsockopt macro
#ifdef _WIN32
// Windows requires const char* for setsockopt
#define SETSOCKOPT_CAST(x) reinterpret_cast<const char*>(x)
#else
// Unix accepts const void* which doesn't need a cast
#define SETSOCKOPT_CAST(x) (x)
#endif

// Constants - Rate limiting like Link
static const char *MULTICAST_IP_V4 = "224.76.78.75";
static const char *MULTICAST_IP_V6 = "ff12::7475"; // Site-local, derived from "TAU5" (0x7475)
static const uint16_t MULTICAST_PORT = 20808;
static const uint32_t MAGIC_HEADER = 0x54415535; // "TAU5"
static const uint8_t PROTOCOL_VERSION = 1;
static const int TTL_SECONDS = 10;
static const int MULTICAST_HOP_LIMIT = 4; // Prevent escape from LAN like Link
static const int MIN_BROADCAST_INTERVAL_MS = 50; // Prevent flooding like Link
static const int NOMINAL_BROADCAST_INTERVAL_MS = 2000;
static const int PEER_CLEANUP_INTERVAL_MS = 1000;
static const int INTERFACE_SCAN_INTERVAL_MS = 5000;
static const uint8_t TTL_RATIO = 20; // TTL/ratio = broadcast frequency like Link
static const int MAX_MESSAGES_PER_SECOND = 100; // Feature 3: Rate limiting
static const size_t MAX_PEERS = 1000; // Feature 5: DoS protection
static const size_t MAX_INFO_STRING_LEN = 1024; // Feature 5: Info string length limit

// Message types
enum MessageType : uint8_t
{
  MSG_ALIVE = 1,
  MSG_RESPONSE = 2,
  MSG_BYEBYE = 3
};

// Enhanced error handling
struct NetworkError : std::runtime_error
{
  std::string interface_name;
  std::string ip_address;

  NetworkError(const std::string &msg, const std::string &iface = "", const std::string &ip = "")
      : std::runtime_error(msg), interface_name(iface), ip_address(ip) {}
};

// Logging
static std::atomic<bool> g_logging_enabled{false};
static std::mutex g_log_mutex;

// Helper function for thread-safe time formatting
inline std::tm* safe_localtime(std::time_t time_val, std::tm* tm_buf) {
#ifdef _WIN32
  return (localtime_s(tm_buf, &time_val) == 0) ? tm_buf : nullptr;
#else
  return std::localtime(&time_val);
#endif
}

#define LOG(msg)                                                   \
  do                                                               \
  {                                                                \
    if (g_logging_enabled.load())                                  \
    {                                                              \
      std::lock_guard<std::mutex> log_lock(g_log_mutex);           \
      auto log_now = std::chrono::system_clock::now();             \
      auto time_t_val = std::chrono::system_clock::to_time_t(log_now); \
      std::tm tm_buf;                                              \
      std::tm* tm_ptr = safe_localtime(time_t_val, &tm_buf);       \
      std::cout << "[TAU5] ";                                      \
      if (tm_ptr)                                                  \
      {                                                            \
        std::cout << std::put_time(tm_ptr, "%H:%M:%S");            \
      }                                                            \
      else                                                         \
      {                                                            \
        std::cout << "??:??:??";                                   \
      }                                                            \
      std::cout << " " << msg << std::endl;                        \
    }                                                              \
  } while (0)

// Simple IPv6 scope checker - Link-compatible behavior (ONLY NEW ADDITION)
class SimpleIPv6ScopeFilter
{
public:
  static bool shouldAcceptMessage(const std::string &sender_ip_str,
                                  const std::string &interface_ip_str)
  {
    try
    {
      auto sender_addr = asio::ip::make_address(sender_ip_str);
      auto interface_addr = asio::ip::make_address(interface_ip_str);

      // IPv4 subnet filtering (existing logic)
      if (sender_addr.is_v4() && interface_addr.is_v4())
      {
        auto sender_v4 = sender_addr.to_v4().to_bytes();
        auto interface_v4 = interface_addr.to_v4().to_bytes();
        // /24 subnet check like Link
        return (sender_v4[0] == interface_v4[0] &&
                sender_v4[1] == interface_v4[1] &&
                sender_v4[2] == interface_v4[2]);
      }

      // IPv6 scope filtering
      if (sender_addr.is_v6() && interface_addr.is_v6())
      {
        auto sender_v6 = sender_addr.to_v6();
        auto interface_v6 = interface_addr.to_v6();

        // Link-local must have matching scope IDs (like Link)
        if (sender_v6.is_link_local())
        {
          return sender_v6.scope_id() == interface_v6.scope_id() ||
                 sender_v6.scope_id() == 0 || interface_v6.scope_id() == 0;
        }

        // Global IPv6 is accepted (like Link)
        return true;
      }

      return false; // Mixed v4/v6
    }
    catch (...)
    {
      return false; // Parse error
    }
  }
};

// UUID generation
std::string generate_uuid()
{
  static thread_local std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  static thread_local std::uniform_int_distribution<> dis(0, 15);

  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < 32; ++i)
  {
    if (i == 8 || i == 12 || i == 16 || i == 20)
      ss << "-";
    ss << dis(gen);
  }
  return ss.str();
}

// Feature 5: UUID validation helper
bool is_valid_uuid(const std::string& uuid)
{
  static const std::regex uuid_regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
  );
  return std::regex_match(uuid, uuid_regex);
}

// Feature 5: UTF-8 validation helper (basic check)
bool is_valid_utf8(const std::string& str)
{
  for (size_t i = 0; i < str.length(); ) {
    unsigned char c = str[i];
    size_t len = 0;

    if ((c & 0x80) == 0) len = 1;
    else if ((c & 0xE0) == 0xC0) len = 2;
    else if ((c & 0xF0) == 0xE0) len = 3;
    else if ((c & 0xF8) == 0xF0) len = 4;
    else return false;

    if (i + len > str.length()) return false;

    for (size_t j = 1; j < len; j++) {
      if ((str[i + j] & 0xC0) != 0x80) return false;
    }

    i += len;
  }
  return true;
}

// Enhanced timer class replacing sleep-based threads
class Timer
{
public:
  using TimePoint = std::chrono::steady_clock::time_point;
  using Duration = std::chrono::milliseconds;

private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  Duration next_interval_;
  std::atomic<bool> interval_changed_{false};

public:
  ~Timer()
  {
    stop();
  }

  template <typename Callback>
  void start(Duration interval, Callback callback)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_.load())
      return;

    running_.store(true);
    next_interval_ = interval;
    thread_ = std::thread([this, callback]()
                          {
            std::unique_lock<std::mutex> lock(mutex_);
            while (running_.load()) {
                auto current_interval = next_interval_;
                if (cv_.wait_for(lock, current_interval, [this] {
                    return !running_.load() || interval_changed_.load();
                })) {
                    if (!running_.load()) {
                        break; // Signaled to stop
                    }
                    if (interval_changed_.load()) {
                        interval_changed_.store(false);
                        continue; // Use new interval
                    }
                }
                if (running_.load()) {
                    lock.unlock();
                    callback();
                    lock.lock();
                }
            } });
  }

  // Reschedule without stopping (safe to call from callback)
  void reschedule(Duration new_interval)
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      next_interval_ = new_interval;
      interval_changed_.store(true);
    }
    cv_.notify_all();
  }

  void stop()
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      running_.store(false);
    }
    cv_.notify_all();

    if (thread_.joinable())
    {
      thread_.join();
    }
  }

  TimePoint now() const
  {
    return std::chrono::steady_clock::now();
  }
};

// Feature 1: Enhanced network interface info with wired/wireless detection
struct InterfaceInfo
{
  std::string name;
  std::string ip_address;
  bool is_ipv6;
  uint32_t scope_id; // For IPv6
  bool is_wired; // Feature 1: new field

  InterfaceInfo(const std::string &n, const std::string &ip, bool v6 = false, uint32_t sid = 0, bool wired = true)
      : name(n), ip_address(ip), is_ipv6(v6), scope_id(sid), is_wired(wired) {}

  bool operator==(const InterfaceInfo &other) const
  {
    return name == other.name && ip_address == other.ip_address &&
           is_ipv6 == other.is_ipv6 && scope_id == other.scope_id &&
           is_wired == other.is_wired; // Feature 1: include in equality
  }

  bool operator<(const InterfaceInfo &other) const
  {
    if (name != other.name)
      return name < other.name;
    if (ip_address != other.ip_address)
      return ip_address < other.ip_address;
    if (is_ipv6 != other.is_ipv6)
      return is_ipv6 < other.is_ipv6;
    if (scope_id != other.scope_id)
      return scope_id < other.scope_id;
    return is_wired < other.is_wired; // Feature 1: include in ordering
  }

  std::string to_string() const
  {
    std::stringstream ss;
    ss << name << "(" << ip_address;
    if (is_ipv6)
      ss << ",IPv6,scope=" << scope_id;
    else
      ss << ",IPv4";
    ss << "," << (is_wired ? "wired" : "wireless"); // Feature 1: display type
    ss << ")";
    return ss.str();
  }
};

// Feature 2: Endpoint struct for multi-homing support
struct Endpoint
{
  std::string ip_address;
  std::string interface_name;
  std::chrono::steady_clock::time_point last_seen;
  bool preferred;
  bool is_wired;

  Endpoint(const std::string& ip, const std::string& iface, bool wired = true)
    : ip_address(ip), interface_name(iface),
      last_seen(std::chrono::steady_clock::now()),
      preferred(false), is_wired(wired) {}
};

// Peer information - Feature 2: Enhanced with multi-endpoint support
struct PeerInfo
{
  std::string peer_id;
  std::string info_string;

  // Feature 2: Multi-endpoint support
  std::vector<Endpoint> endpoints;
  std::chrono::steady_clock::time_point last_info_refresh;

  // Legacy fields for ABI compatibility
  std::string ip_address;
  std::string interface_name;
  std::chrono::steady_clock::time_point last_seen;

  PeerInfo(const std::string &id, const std::string &info, const std::string &ip, const std::string &iface, bool is_wired = true)
      : peer_id(id), info_string(info),
        last_info_refresh(std::chrono::steady_clock::now()),
        ip_address(ip), interface_name(iface),
        last_seen(std::chrono::steady_clock::now())
  {
    // Initialize with first endpoint
    endpoints.emplace_back(ip, iface, is_wired);
  }

  // Feature 2: Endpoint selection logic
  const Endpoint* select_endpoint() const
  {
    if (endpoints.empty()) return nullptr;

    // 1. Explicit preferred wins
    for (const auto& ep : endpoints) {
      if (ep.preferred) return &ep;
    }

    // 2. Wired before wireless
    const Endpoint* best_wired = nullptr;
    const Endpoint* best_wireless = nullptr;

    for (const auto& ep : endpoints) {
      if (ep.is_wired) {
        if (!best_wired || ep.last_seen > best_wired->last_seen) {
          best_wired = &ep;
        }
      } else {
        if (!best_wireless || ep.last_seen > best_wireless->last_seen) {
          best_wireless = &ep;
        }
      }
    }

    if (best_wired) return best_wired;
    if (best_wireless) return best_wireless;

    // 3. Freshest last_seen
    return &(*std::max_element(endpoints.begin(), endpoints.end(),
      [](const Endpoint& a, const Endpoint& b) {
        return a.last_seen < b.last_seen;
      }));
  }

  // Feature 2: Sync legacy fields with selected endpoint
  void sync_with_selected_endpoint()
  {
    const Endpoint* ep = select_endpoint();
    if (ep) {
      ip_address = ep->ip_address;
      interface_name = ep->interface_name;
      last_seen = ep->last_seen;
    }
  }
};

// Message protocol
struct Message
{
  uint32_t magic;
  uint8_t version;
  uint8_t type;
  uint16_t info_length;
  std::string peer_id;
  std::string info_string;

  Message() : magic(MAGIC_HEADER), version(PROTOCOL_VERSION), type(MSG_ALIVE), info_length(0) {}

  std::vector<uint8_t> serialize() const
  {
    std::vector<uint8_t> data;
    data.reserve(8 + 36 + info_string.length());

    uint32_t net_magic = htonl(magic);
    data.insert(data.end(), reinterpret_cast<uint8_t *>(&net_magic), reinterpret_cast<uint8_t *>(&net_magic) + 4);

    data.push_back(version);
    data.push_back(type);

    uint16_t net_length = htons(static_cast<uint16_t>(info_string.length()));
    data.insert(data.end(), reinterpret_cast<uint8_t *>(&net_length), reinterpret_cast<uint8_t *>(&net_length) + 2);

    std::string padded_id = peer_id;
    padded_id.resize(36, '\0');
    data.insert(data.end(), padded_id.begin(), padded_id.end());

    data.insert(data.end(), info_string.begin(), info_string.end());

    return data;
  }

  bool deserialize(const uint8_t *buffer, size_t length)
  {
    if (length < 8 + 36)
      return false;

    uint32_t net_magic;
    memcpy(&net_magic, buffer, 4);
    magic = ntohl(net_magic);
    if (magic != MAGIC_HEADER)
      return false;

    version = buffer[4];
    if (version != PROTOCOL_VERSION)
      return false;

    type = buffer[5];

    uint16_t net_length;
    memcpy(&net_length, buffer + 6, 2);
    info_length = ntohs(net_length);

    if (length < 8 + 36 + info_length)
      return false;

    peer_id.assign(reinterpret_cast<const char *>(buffer + 8), 36);
    size_t null_pos = peer_id.find('\0');
    if (null_pos != std::string::npos)
    {
      peer_id.resize(null_pos);
    }

    if (info_length > 0)
    {
      info_string.assign(reinterpret_cast<const char *>(buffer + 8 + 36), info_length);
    }

    return true;
  }
};

// Forward declarations
class DiscoveryService;

// Enhanced network interface with proper IPv6 scope handling and error recovery
class NetworkInterface
{
private:
  InterfaceInfo info_;
  socket_t socket_fd_;        // multicast socket
  socket_t unicast_socket_fd_; // unicast socket for responses
  std::thread receive_thread_;
  std::atomic<bool> running_;
  DiscoveryService *service_;
  std::atomic<int> error_count_{0};

  // Feature 3: Rate limiting
  mutable std::mutex rate_mtx_;
  std::chrono::steady_clock::time_point last_rate_reset_;
  std::atomic<int> msgs_this_sec_{0};

public:
  NetworkInterface(const InterfaceInfo &info, DiscoveryService *service)
      : info_(info), socket_fd_(INVALID_SOCKET_VALUE), unicast_socket_fd_(INVALID_SOCKET_VALUE),
        running_(false), service_(service), last_rate_reset_(std::chrono::steady_clock::now()) {}

  ~NetworkInterface()
  {
    stop();
  }

  bool start();
  void stop();
  bool send_message(const Message &msg);
  bool send_unicast_message(const Message &msg, const std::string &target_ip);
  void receive_loop();
  bool needs_repair() const { return error_count_.load() > 3; }
  void reset_error_count() { error_count_.store(0); }

  const InterfaceInfo &info() const { return info_; }
  bool is_running() const { return running_.load(); }
};

// Enhanced peer manager with better lifecycle management
class PeerManager
{
private:
  mutable std::mutex peers_mutex_;
  std::map<std::string, std::unique_ptr<PeerInfo>> peers_;

public:
  // ENHANCED: Return both is_new and peer_count_changed for better callback logic
  struct PeerUpdateResult
  {
    bool is_new;
    bool peer_list_changed;
    size_t total_peers;
  };

  PeerUpdateResult add_or_update_peer(const std::string &peer_id, const std::string &info_string,
                                      const std::string &ip_address, const std::string &interface_name,
                                      bool is_wired = true) // Feature 1: add wired flag
  {
    // Feature 5: Input validation
    if (!is_valid_uuid(peer_id)) {
      LOG("Rejected invalid peer ID format: " << peer_id);
      return {false, false, peers_.size()};
    }

    if (info_string.size() > MAX_INFO_STRING_LEN) {
      LOG("Rejected oversized info string from peer: " << peer_id);
      return {false, false, peers_.size()};
    }

    if (!is_valid_utf8(info_string)) {
      LOG("Rejected invalid UTF-8 info string from peer: " << peer_id);
      return {false, false, peers_.size()};
    }

    std::lock_guard<std::mutex> lock(peers_mutex_);

    // Feature 5: MAX_PEERS limit
    if (peers_.size() >= MAX_PEERS && peers_.find(peer_id) == peers_.end()) {
      LOG("Rejected new peer due to MAX_PEERS limit: " << peer_id);
      return {false, false, peers_.size()};
    }

    auto it = peers_.find(peer_id);
    bool is_new = (it == peers_.end());
    bool peer_list_changed = false;

    if (it != peers_.end())
    {
      // Feature 2: Multi-endpoint update logic
      auto& peer = *it->second;

      // Find or create endpoint
      auto ep_it = std::find_if(peer.endpoints.begin(), peer.endpoints.end(),
        [&](const Endpoint& ep) {
          return ep.ip_address == ip_address && ep.interface_name == interface_name;
        });

      if (ep_it != peer.endpoints.end()) {
        // Update existing endpoint
        ep_it->last_seen = std::chrono::steady_clock::now();
        ep_it->is_wired = is_wired;
      } else {
        // Add new endpoint
        peer.endpoints.emplace_back(ip_address, interface_name, is_wired);
        LOG("Added new endpoint for peer " << peer_id << ": " << ip_address << " on " << interface_name);
      }

      // Feature 6: Only trigger callback for info changes
      bool info_actually_changed = (peer.info_string != info_string);

      if (info_actually_changed) {
        peer.info_string = info_string;
        peer.last_info_refresh = std::chrono::steady_clock::now();
        peer_list_changed = true;
        LOG("Peer info updated: " << peer_id << " (" << info_string << ")");
      }

      // Always sync legacy fields
      peer.sync_with_selected_endpoint();
    }
    else
    {
      // New peer - this should trigger callback
      peers_[peer_id] = std::make_unique<PeerInfo>(peer_id, info_string, ip_address, interface_name, is_wired);
      peer_list_changed = true;
      LOG("New peer discovered: " << peer_id << " (" << info_string << ") from " << ip_address << " on " << interface_name);
    }

    return {is_new, peer_list_changed, peers_.size()};
  }

  bool remove_peer(const std::string &peer_id)
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it != peers_.end())
    {
      LOG("Peer removed: " << peer_id << " (" << it->second->info_string << ")");
      peers_.erase(it);
      return true;
    }
    return false;
  }

  // Feature 2: Enhanced cleanup for multi-endpoint support
  size_t cleanup_expired_peers()
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto ttl = std::chrono::seconds(TTL_SECONDS);

    size_t removed_count = 0;
    auto it = peers_.begin();
    while (it != peers_.end())
    {
      auto& peer = *it->second;

      // First remove expired endpoints
      peer.endpoints.erase(
        std::remove_if(peer.endpoints.begin(), peer.endpoints.end(),
          [&](const Endpoint& ep) {
            bool expired = (now - ep.last_seen) > ttl;
            if (expired) {
              LOG("Endpoint expired for peer " << peer.peer_id << ": " << ep.ip_address);
            }
            return expired;
          }),
        peer.endpoints.end()
      );

      // Remove peer if no endpoints remain
      if (peer.endpoints.empty()) {
        LOG("Peer timed out (no endpoints): " << it->first << " (" << peer.info_string << ")");
        it = peers_.erase(it);
        removed_count++;
      } else {
        // Update legacy fields
        peer.sync_with_selected_endpoint();
        ++it;
      }
    }

    return removed_count;
  }

  std::vector<PeerInfo> get_all_peers() const
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<PeerInfo> result;
    result.reserve(peers_.size());

    for (const auto &pair : peers_)
    {
      result.push_back(*pair.second);
    }

    return result;
  }

  size_t count() const
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return peers_.size();
  }

  // Feature 2: Public method to mark an endpoint as preferred
  bool mark_endpoint_preferred(const std::string& peer_id, const std::string& ip_address,
                               const std::string& interface_name)
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
      return false;
    }

    auto& peer = *it->second;
    bool found = false;

    // Clear all preferred flags first
    for (auto& ep : peer.endpoints) {
      ep.preferred = false;
    }

    // Find and mark the specified endpoint
    for (auto& ep : peer.endpoints) {
      if (ep.ip_address == ip_address && ep.interface_name == interface_name) {
        ep.preferred = true;
        found = true;
        break;
      }
    }

    if (found) {
      peer.sync_with_selected_endpoint();
      LOG("Marked endpoint as preferred for peer " << peer_id << ": " << ip_address << " on " << interface_name);
    }

    return found;
  }
};

// Interface manager with dynamic scanning and repair
class InterfaceManager
{
private:
  mutable std::mutex interfaces_mutex_;
  std::map<InterfaceInfo, std::unique_ptr<NetworkInterface>> interfaces_;
  DiscoveryService *service_;
  Timer scan_timer_;

public:
  InterfaceManager(DiscoveryService *service) : service_(service) {}

  ~InterfaceManager()
  {
    stop_all();
  }

  void start_scanning();
  void stop_scanning();
  void stop_all();
  void scan_interfaces();
  void repair_failed_interfaces();
  bool send_on_all_interfaces(const Message &msg);
  bool send_unicast_on_interface(const Message &msg, const std::string &target_ip, const std::string &interface_name);
  std::vector<InterfaceInfo> get_current_interfaces() const;

private:
  std::vector<InterfaceInfo> enumerate_interfaces();
  void add_interface(const InterfaceInfo &info);
  void remove_interface(const InterfaceInfo &info);
};

// Main discovery service with enhanced architecture
class DiscoveryService
{
private:
  std::atomic<bool> running_;
  std::string my_peer_id_;
  std::string my_info_string_;
  std::unique_ptr<InterfaceManager> interface_manager_;
  std::unique_ptr<PeerManager> peer_manager_;
  Timer broadcast_timer_;
  Timer cleanup_timer_;
  std::chrono::steady_clock::time_point last_broadcast_time_;

public:
  DiscoveryService() : running_(false), peer_manager_(std::make_unique<PeerManager>()),
                       last_broadcast_time_(std::chrono::steady_clock::now())
  {
    my_peer_id_ = generate_uuid();
    interface_manager_ = std::make_unique<InterfaceManager>(this);
    LOG("Discovery service created with peer ID: " << my_peer_id_);
  }

  ~DiscoveryService()
  {
    stop();
  }

  bool start(const std::string &info_string);
  void stop();
  std::vector<PeerInfo> get_peers() const;
  void handle_received_message(const Message &msg, const std::string &sender_ip, const std::string &interface_name, bool is_wired);

  // Feature 2: Mark endpoint as preferred
  bool mark_endpoint_preferred(const std::string& peer_id, const std::string& ip_address,
                               const std::string& interface_name)
  {
    return peer_manager_->mark_endpoint_preferred(peer_id, ip_address, interface_name);
  }

  // Interface manager callbacks
  void on_interface_added(const InterfaceInfo &info)
  {
    LOG("Interface added: " << info.to_string());
  }

  void on_interface_removed(const InterfaceInfo &info)
  {
    LOG("Interface removed: " << info.to_string());
  }

  // DEBUGGING: Add callback diagnostic functions
  void debug_callback_state() const
  {
    LOG("Callback debug - notifications_enabled=" << notifications_enabled() << " peer_count=" << peer_manager_->count());
  }

private:
  void broadcast_alive();
  void cleanup_peers();
};

// Global service instance
static std::unique_ptr<DiscoveryService> g_service;
static std::mutex g_service_mutex;

#ifdef __APPLE__
// Proper WiFi detection for macOS using interface media type
bool is_wireless(const char* ifname)
{
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) return false;

  struct ifmediareq ifmr;
  memset(&ifmr, 0, sizeof(ifmr));
  strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

  bool wifi = (ioctl(s, SIOCGIFMEDIA, &ifmr) == 0) &&
              (ifmr.ifm_current & IFM_IEEE80211);

  close(s);
  return wifi;
}
#endif

// NetworkInterface implementation with enhanced IPv6 and error handling
bool NetworkInterface::start()
{
  if (running_.load())
    return true;

  LOG("Starting interface: " << info_.to_string());

  try
  {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
      throw NetworkError("WSAStartup failed", info_.name, info_.ip_address);
    }
#endif

    int family = info_.is_ipv6 ? AF_INET6 : AF_INET;

    // Create multicast socket
    socket_fd_ = socket(family, SOCK_DGRAM, 0);
    if (socket_fd_ == INVALID_SOCKET_VALUE)
    {
      throw NetworkError("Failed to create multicast socket", info_.name, info_.ip_address);
    }

    // Create unicast socket
    unicast_socket_fd_ = socket(family, SOCK_DGRAM, 0);
    if (unicast_socket_fd_ == INVALID_SOCKET_VALUE)
    {
      throw NetworkError("Failed to create unicast socket", info_.name, info_.ip_address);
    }

    // Set socket options for multicast socket
    int reuse = 1;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse), sizeof(reuse)) < 0)
    {
      LOG("Warning: Failed to set SO_REUSEADDR for multicast socket " << info_.name);
    }

#ifdef SO_REUSEPORT
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuse), sizeof(reuse)) < 0)
    {
      LOG("Warning: Failed to set SO_REUSEPORT for multicast socket " << info_.name);
    }
#endif

    // Set multicast TTL
    if (info_.is_ipv6)
    {
      int hops = MULTICAST_HOP_LIMIT;
      if (setsockopt(socket_fd_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, reinterpret_cast<const char *>(&hops), sizeof(hops)) < 0)
      {
        LOG("Warning: Failed to set IPv6 multicast hops for interface " << info_.name);
      }
    }
    else
    {
      int ttl = MULTICAST_HOP_LIMIT;
      if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl)) < 0)
      {
        LOG("Warning: Failed to set IPv4 multicast TTL for interface " << info_.name);
      }
    }

    // CRITICAL FIX: Bind multicast sockets to the correct interface
    if (info_.is_ipv6)
    {
      unsigned int idx = info_.scope_id;
      if (setsockopt(socket_fd_, IPPROTO_IPV6, IPV6_MULTICAST_IF, SETSOCKOPT_CAST(&idx), sizeof(idx)) < 0)
      {
        LOG("Warning: Failed to set IPv6 multicast interface for " << info_.name);
      }
    }
    else
    {
      struct in_addr localIf;
      inet_pton(AF_INET, info_.ip_address.c_str(), &localIf);
      if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF, SETSOCKOPT_CAST(&localIf), sizeof(localIf)) < 0)
      {
        LOG("Warning: Failed to set IPv4 multicast interface for " << info_.name);
      }
    }

    // Bind multicast socket
    if (info_.is_ipv6)
    {
      struct sockaddr_in6 addr = {};
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons(MULTICAST_PORT);
      addr.sin6_addr = in6addr_any;

      if (bind(socket_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0)
      {
        throw NetworkError("Failed to bind IPv6 multicast socket", info_.name, info_.ip_address);
      }

      // Join multicast group with proper scope handling
      struct ipv6_mreq mreq = {};
      inet_pton(AF_INET6, MULTICAST_IP_V6, &mreq.ipv6mr_multiaddr);
      mreq.ipv6mr_interface = info_.scope_id;

      if (setsockopt(socket_fd_, IPPROTO_IPV6, IPV6_JOIN_GROUP, reinterpret_cast<const char *>(&mreq), sizeof(mreq)) < 0)
      {
        LOG("Warning: Failed to join IPv6 multicast group for interface " << info_.name);
      }
      else
      {
        LOG("Joined IPv6 multicast group on interface " << info_.name << " (scope_id=" << info_.scope_id << ")");
      }

      // Bind unicast socket to specific interface IP
      struct sockaddr_in6 unicast_addr = {};
      unicast_addr.sin6_family = AF_INET6;
      unicast_addr.sin6_port = htons(0); // Let system assign port
      inet_pton(AF_INET6, info_.ip_address.c_str(), &unicast_addr.sin6_addr);
      unicast_addr.sin6_scope_id = info_.scope_id;

      if (bind(unicast_socket_fd_, reinterpret_cast<struct sockaddr *>(&unicast_addr), sizeof(unicast_addr)) < 0)
      {
        LOG("Warning: Failed to bind IPv6 unicast socket to " << info_.ip_address);
      }
    }
    else
    {
      struct sockaddr_in addr = {};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(MULTICAST_PORT);
      addr.sin_addr.s_addr = INADDR_ANY;

      if (bind(socket_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0)
      {
        throw NetworkError("Failed to bind IPv4 multicast socket", info_.name, info_.ip_address);
      }

      // Join multicast group
      struct ip_mreq mreq = {};
      inet_pton(AF_INET, MULTICAST_IP_V4, &mreq.imr_multiaddr);
      inet_pton(AF_INET, info_.ip_address.c_str(), &mreq.imr_interface);

      if (setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char *>(&mreq), sizeof(mreq)) < 0)
      {
        LOG("Warning: Failed to join IPv4 multicast group for interface " << info_.name);
      }
      else
      {
        LOG("Joined IPv4 multicast group on interface " << info_.name);
      }

      // Bind unicast socket to specific interface IP
      struct sockaddr_in unicast_addr = {};
      unicast_addr.sin_family = AF_INET;
      unicast_addr.sin_port = htons(0); // Let system assign port
      inet_pton(AF_INET, info_.ip_address.c_str(), &unicast_addr.sin_addr);

      if (bind(unicast_socket_fd_, reinterpret_cast<struct sockaddr *>(&unicast_addr), sizeof(unicast_addr)) < 0)
      {
        LOG("Warning: Failed to bind IPv4 unicast socket to " << info_.ip_address);
      }
    }

    running_.store(true);
    error_count_.store(0);
    receive_thread_ = std::thread(&NetworkInterface::receive_loop, this);

    LOG("Interface started successfully with dual sockets: " << info_.to_string());
    return true;
  }
  catch (const NetworkError &e)
  {
    LOG("Failed to start interface " << info_.to_string() << ": " << e.what());
    if (socket_fd_ != INVALID_SOCKET_VALUE)
    {
      close_socket(socket_fd_);
      socket_fd_ = INVALID_SOCKET_VALUE;
    }
    if (unicast_socket_fd_ != INVALID_SOCKET_VALUE)
    {
      close_socket(unicast_socket_fd_);
      unicast_socket_fd_ = INVALID_SOCKET_VALUE;
    }
    error_count_.fetch_add(1);
    return false;
  }
}

void NetworkInterface::stop()
{
  if (!running_.load())
    return;

  LOG("Stopping interface: " << info_.to_string());
  running_.store(false);

  if (socket_fd_ != INVALID_SOCKET_VALUE)
  {
    close_socket(socket_fd_);
    socket_fd_ = INVALID_SOCKET_VALUE;
  }

  if (unicast_socket_fd_ != INVALID_SOCKET_VALUE)
  {
    close_socket(unicast_socket_fd_);
    unicast_socket_fd_ = INVALID_SOCKET_VALUE;
  }

  if (receive_thread_.joinable())
  {
    receive_thread_.join();
  }

  LOG("Interface stopped: " << info_.to_string());
}

bool NetworkInterface::send_message(const Message &msg)
{
  if (!running_.load() || socket_fd_ == INVALID_SOCKET_VALUE)
  {
    error_count_.fetch_add(1);
    return false;
  }

  try
  {
    auto data = msg.serialize();

    if (info_.is_ipv6)
    {
      struct sockaddr_in6 addr = {};
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons(MULTICAST_PORT);
      inet_pton(AF_INET6, MULTICAST_IP_V6, &addr.sin6_addr);
      addr.sin6_scope_id = info_.scope_id;

      ssize_t sent = sendto(socket_fd_, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0,
                            reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));

      if (sent != static_cast<ssize_t>(data.size()))
      {
        throw NetworkError("IPv6 sendto failed", info_.name, info_.ip_address);
      }
    }
    else
    {
      struct sockaddr_in addr = {};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(MULTICAST_PORT);
      inet_pton(AF_INET, MULTICAST_IP_V4, &addr.sin_addr);

      ssize_t sent = sendto(socket_fd_, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0,
                            reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));

      if (sent != static_cast<ssize_t>(data.size()))
      {
        throw NetworkError("IPv4 sendto failed", info_.name, info_.ip_address);
      }
    }

    return true;
  }
  catch (const NetworkError &e)
  {
    LOG("Send failed on interface " << info_.to_string() << ": " << e.what());
    error_count_.fetch_add(1);
    return false;
  }
}

bool NetworkInterface::send_unicast_message(const Message &msg, const std::string &target_ip)
{
  if (!running_.load() || unicast_socket_fd_ == INVALID_SOCKET_VALUE)
  {
    error_count_.fetch_add(1);
    return false;
  }

  try
  {
    auto data = msg.serialize();

    if (info_.is_ipv6)
    {
      // Feature 4: Strip scope suffix before inet_pton
      std::string clean = target_ip;
      auto pct = clean.find('%');
      if (pct != std::string::npos) clean.resize(pct);

      struct sockaddr_in6 addr = {};
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons(MULTICAST_PORT);
      inet_pton(AF_INET6, clean.c_str(), &addr.sin6_addr);
      addr.sin6_scope_id = info_.scope_id;

      ssize_t sent = sendto(unicast_socket_fd_, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0,
                            reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));

      if (sent != static_cast<ssize_t>(data.size()))
      {
        throw NetworkError("IPv6 unicast sendto failed", info_.name, info_.ip_address);
      }
    }
    else
    {
      struct sockaddr_in addr = {};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(MULTICAST_PORT);
      inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);

      ssize_t sent = sendto(unicast_socket_fd_, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0,
                            reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));

      if (sent != static_cast<ssize_t>(data.size()))
      {
        throw NetworkError("IPv4 unicast sendto failed", info_.name, info_.ip_address);
      }
    }

    return true;
  }
  catch (const NetworkError &e)
  {
    LOG("Unicast send failed on interface " << info_.to_string() << ": " << e.what());
    error_count_.fetch_add(1);
    return false;
  }
}

// MINIMAL CHANGE: Enhanced receive_loop with simple ASIO IPv6 filtering
void NetworkInterface::receive_loop()
{
  LOG("Receive loop started for interface: " << info_.to_string());

  uint8_t buffer[1024];

  while (running_.load())
  {
    try
    {
      // Feature 3: Rate limiting check
      {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_rate_reset_);

        if (elapsed >= std::chrono::seconds(1)) {
          std::lock_guard<std::mutex> lock(rate_mtx_);
          last_rate_reset_ = now;
          msgs_this_sec_.store(0);
        }

        if (msgs_this_sec_.load() >= MAX_MESSAGES_PER_SECOND) {
          // Drop packet by reading and discarding it
          // IMPORTANT: Must actually drain the datagram to prevent kernel queue growth
          struct sockaddr_storage trash_addr;
          socklen_t trash_len = sizeof(trash_addr);
          recvfrom(socket_fd_, reinterpret_cast<char *>(buffer), sizeof(buffer), 0,
                   reinterpret_cast<struct sockaddr *>(&trash_addr), &trash_len);
          continue;
        }
      }

      struct sockaddr_storage sender_addr = {};
      socklen_t addr_len = sizeof(sender_addr);

      ssize_t received = recvfrom(socket_fd_, reinterpret_cast<char *>(buffer), sizeof(buffer), 0,
                                  reinterpret_cast<struct sockaddr *>(&sender_addr), &addr_len);

      if (received <= 0)
      {
        if (running_.load())
        {
          throw NetworkError("Receive error", info_.name, info_.ip_address);
        }
        continue;
      }

      // Feature 3: Increment message counter
      msgs_this_sec_.fetch_add(1);

      // Parse sender IP
      std::string sender_ip;

      if (sender_addr.ss_family == AF_INET)
      {
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(&sender_addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
        sender_ip = ip_str;
      }
      else if (sender_addr.ss_family == AF_INET6)
      {
        char ip_str[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = reinterpret_cast<struct sockaddr_in6 *>(&sender_addr);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        sender_ip = ip_str;

        // For IPv6, include scope in the sender_ip string if it has one
        try
        {
          auto sender_asio_addr = asio::ip::make_address_v6(sender_ip);
          sender_asio_addr.scope_id(addr_in6->sin6_scope_id);
          sender_ip = sender_asio_addr.to_string(); // This will include scope if needed
        }
        catch (const std::exception &e)
        {
          LOG("Failed to parse IPv6 sender address: " << e.what());
          continue;
        }
      }

      // Skip messages from ourselves
      if (sender_ip == info_.ip_address)
      {
        continue;
      }

      // SIMPLE ASIO-based scope filtering (ONLY CHANGED LINE!)
      if (!SimpleIPv6ScopeFilter::shouldAcceptMessage(sender_ip, info_.ip_address))
      {
        LOG("Filtered message from " << sender_ip << " on " << info_.name);
        continue;
      }

      // Parse message
      Message msg;
      if (msg.deserialize(buffer, received))
      {
        if (service_)
        {
          service_->handle_received_message(msg, sender_ip, info_.name, info_.is_wired);
        }
      }

      // Reset error count on successful receive
      error_count_.store(0);
    }
    catch (const NetworkError &e)
    {
      if (running_.load())
      {
        LOG("Receive error on interface " << info_.to_string() << ": " << e.what());
        error_count_.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  }

  LOG("Receive loop ended for interface: " << info_.to_string());
}

// InterfaceManager implementation
void InterfaceManager::start_scanning()
{
  LOG("Starting interface scanning...");

  // Do initial scan
  scan_interfaces();

  // Start periodic scanning
  scan_timer_.start(std::chrono::milliseconds(INTERFACE_SCAN_INTERVAL_MS), [this]()
                    {
        scan_interfaces();
        repair_failed_interfaces(); });
}

void InterfaceManager::stop_scanning()
{
  LOG("Stopping interface scanning...");
  scan_timer_.stop();
}

void InterfaceManager::stop_all()
{
  stop_scanning();

  std::lock_guard<std::mutex> lock(interfaces_mutex_);
  for (auto &pair : interfaces_)
  {
    pair.second->stop();
  }
  interfaces_.clear();
  LOG("All interfaces stopped");
}

void InterfaceManager::scan_interfaces()
{
  auto current_interfaces = enumerate_interfaces();
  std::set<InterfaceInfo> current_set(current_interfaces.begin(), current_interfaces.end());

  std::lock_guard<std::mutex> lock(interfaces_mutex_);

  // Find interfaces to remove
  std::vector<InterfaceInfo> to_remove;
  for (const auto &pair : interfaces_)
  {
    if (current_set.find(pair.first) == current_set.end())
    {
      to_remove.push_back(pair.first);
    }
  }

  // Remove stale interfaces
  for (const auto &info : to_remove)
  {
    remove_interface(info);
  }

  // Add new interfaces
  for (const auto &info : current_interfaces)
  {
    if (interfaces_.find(info) == interfaces_.end())
    {
      add_interface(info);
    }
  }
}

void InterfaceManager::repair_failed_interfaces()
{
  std::lock_guard<std::mutex> lock(interfaces_mutex_);

  std::vector<InterfaceInfo> to_repair;
  for (const auto &pair : interfaces_)
  {
    if (pair.second->needs_repair())
    {
      to_repair.push_back(pair.first);
    }
  }

  for (const auto &info : to_repair)
  {
    LOG("Repairing failed interface: " << info.to_string());
    remove_interface(info);
    add_interface(info);
  }
}

bool InterfaceManager::send_on_all_interfaces(const Message &msg)
{
  std::lock_guard<std::mutex> lock(interfaces_mutex_);

  bool any_success = false;
  for (auto &pair : interfaces_)
  {
    if (pair.second->is_running())
    {
      if (pair.second->send_message(msg))
      {
        any_success = true;
      }
    }
  }

  return any_success;
}

bool InterfaceManager::send_unicast_on_interface(const Message &msg, const std::string &target_ip, const std::string &interface_name)
{
  std::lock_guard<std::mutex> lock(interfaces_mutex_);

  // Determine if target is IPv6
  bool target_is_ipv6 = target_ip.find(':') != std::string::npos;

  for (auto &pair : interfaces_)
  {
    if (pair.first.name == interface_name &&
        pair.first.is_ipv6 == target_is_ipv6 &&  // Match IP version
        pair.second->is_running())
    {
      return pair.second->send_unicast_message(msg, target_ip);
    }
  }
  return false;
}

std::vector<InterfaceInfo> InterfaceManager::get_current_interfaces() const
{
  std::lock_guard<std::mutex> lock(interfaces_mutex_);

  std::vector<InterfaceInfo> result;
  result.reserve(interfaces_.size());

  for (const auto &pair : interfaces_)
  {
    if (pair.second->is_running())
    {
      result.push_back(pair.first);
    }
  }

  return result;
}

// FIXED: Interface enumeration to include link-local IPv6
std::vector<InterfaceInfo> InterfaceManager::enumerate_interfaces()
{
  std::vector<InterfaceInfo> interfaces;

#ifdef _WIN32
  ULONG bufferSize = 0;
  GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufferSize);

  std::vector<uint8_t> buffer(bufferSize);
  PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &bufferSize) == NO_ERROR)
  {
    // First pass: collect all potential interfaces
    std::vector<InterfaceInfo> candidates;

    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next)
    {
      if (adapter->OperStatus != IfOperStatusUp)
        continue;

      // Feature 1: Detect wired/wireless on Windows
      bool is_wired = (adapter->IfType == IF_TYPE_ETHERNET_CSMACD);

      for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
      {
        if (addr->Address.lpSockaddr->sa_family == AF_INET)
        {
          struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr->Address.lpSockaddr);
          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);

          std::string ip(ip_str);
          if (ip != "127.0.0.1")
          {
            std::wstring wname(adapter->FriendlyName);
            std::string name(wname.begin(), wname.end());
            candidates.emplace_back(name, ip, false, 0, is_wired);
          }
        }
        else if (addr->Address.lpSockaddr->sa_family == AF_INET6)
        {
          struct sockaddr_in6 *addr_in6 = reinterpret_cast<struct sockaddr_in6 *>(addr->Address.lpSockaddr);
          char ip_str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);

          std::string ip(ip_str);
          if (ip != "::1")
          { // Only exclude loopback
            std::wstring wname(adapter->FriendlyName);
            std::string name(wname.begin(), wname.end());
            candidates.emplace_back(name, ip, true, adapter->Ipv6IfIndex, is_wired);
          }
        }
      }
    }

    // Second pass: filter IPv6 addresses to prefer link-local over global per interface
    std::map<std::string, bool> interface_has_link_local;

    // First, identify which interfaces have link-local addresses
    for (const auto& candidate : candidates) {
      if (candidate.is_ipv6 && candidate.ip_address.substr(0, 5) == "fe80:") {
        interface_has_link_local[candidate.name] = true;
      }
    }

    // Then, add interfaces based on priority: link-local preferred over global
    for (const auto& candidate : candidates) {
      bool should_add = true;

      if (candidate.is_ipv6) {
        bool is_link_local = (candidate.ip_address.substr(0, 5) == "fe80:");
        bool has_link_local = interface_has_link_local[candidate.name];

        // If this interface has link-local available, only add the link-local address
        if (has_link_local && !is_link_local) {
          should_add = false;  // Skip global IPv6 if link-local exists
        }
      }

      if (should_add) {
        interfaces.push_back(candidate);
        if (candidate.is_ipv6) {
          LOG("Found IPv6 interface: " << candidate.name << " " << candidate.ip_address << " scope=" << candidate.scope_id);
        }
      }
    }
  }
#else
  struct ifaddrs *ifaddr;
  if (getifaddrs(&ifaddr) == 0)
  {
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
      if (!ifa->ifa_addr)
        continue;
      if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
        continue;

      // Feature 1: Detect wired/wireless using improved method
      bool is_wired = true;  // Default to wired

#ifdef __linux__
      // Try wireless ioctl first
      int sock = socket(AF_INET, SOCK_DGRAM, 0);
      if (sock >= 0) {
        struct iwreq wrq;
        memset(&wrq, 0, sizeof(wrq));
        strncpy(wrq.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIWNAME, &wrq) >= 0) {
          is_wired = false;  // Wireless ioctl succeeded
        } else {
          // Fallback to /sys check
          std::string sys_path = "/sys/class/net/" + std::string(ifa->ifa_name) + "/wireless";
          std::ifstream wireless_check(sys_path);
          if (wireless_check.good()) {
            is_wired = false;
          }
        }
        close(sock);
      }
#elif defined(__APPLE__)
      // Feature 1: Use proper WiFi detection on macOS
      is_wired = !is_wireless(ifa->ifa_name);
#endif

      if (ifa->ifa_addr->sa_family == AF_INET)
      {
        // Skip VPN tunnel interfaces
        if (strncmp(ifa->ifa_name, "utun", 4) == 0) {
          continue;
        }

        struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);

        std::string ip(ip_str);
        if (ip != "127.0.0.1")
        {
          interfaces.emplace_back(ifa->ifa_name, ip, false, 0, is_wired);
        }
      }
      else if (ifa->ifa_addr->sa_family == AF_INET6)
      {
        // Skip VPN tunnel interfaces
        if (strncmp(ifa->ifa_name, "utun", 4) == 0) {
          continue;
        }

        // Skip Apple-specific interfaces that can cause message duplication
        if (strncmp(ifa->ifa_name, "awdl", 4) == 0 ||  // Apple Wireless Direct Link (AirDrop)
            strncmp(ifa->ifa_name, "llw", 3) == 0) {   // Low Latency WLAN
          continue;
        }

        struct sockaddr_in6 *addr_in6 = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);

        std::string ip(ip_str);
        // FIXED: Include link-local IPv6 addresses (fe80::) like Link does
        if (ip != "::1")
        { // Only exclude loopback

          // Filter IPv6 addresses like Link does - prefer link-local over global addresses
          bool skip_address = false;

          // Check if this is a global IPv6 address (not link-local)
          bool is_link_local = (ip.substr(0, 5) == "fe80:");

          if (!is_link_local) {
            // This is a global IPv6 address - check if we already have a link-local for this interface
            for (const auto& existing : interfaces) {
              if (existing.name == ifa->ifa_name && existing.is_ipv6) {
                std::string existing_ip = existing.ip_address;
                if (existing_ip.substr(0, 5) == "fe80:") {
                  skip_address = true;  // Skip global if we already have link-local
                  break;
                }
              }
            }
          }

          if (!skip_address) {
            uint32_t scope_id = if_nametoindex(ifa->ifa_name);
            interfaces.emplace_back(ifa->ifa_name, ip, true, scope_id, is_wired);
            LOG("Found IPv6 interface: " << ifa->ifa_name << " " << ip << " scope=" << scope_id);
          }
        }
      }
    }
    freeifaddrs(ifaddr);
  }
#endif

  return interfaces;
}

void InterfaceManager::add_interface(const InterfaceInfo &info)
{
  auto iface = std::make_unique<NetworkInterface>(info, service_);
  if (iface->start())
  {
    interfaces_[info] = std::move(iface);
    service_->on_interface_added(info);
  }
}

void InterfaceManager::remove_interface(const InterfaceInfo &info)
{
  auto it = interfaces_.find(info);
  if (it != interfaces_.end())
  {
    it->second->stop();
    interfaces_.erase(it);
    service_->on_interface_removed(info);
  }
}

// DiscoveryService implementation
bool DiscoveryService::start(const std::string &info_string)
{
  if (running_.load())
    return true;

  my_info_string_ = info_string;
  LOG("Starting discovery service with info: '" << info_string << "'");

  // Start interface management
  interface_manager_->start_scanning();

  auto interfaces = interface_manager_->get_current_interfaces();
  if (interfaces.empty())
  {
    LOG("Warning: No network interfaces available initially");
    // Don't fail - interfaces might be added later
  }

  running_.store(true);

  // Send initial broadcast immediately
  Message initial_alive;
  initial_alive.type = MSG_ALIVE;
  initial_alive.peer_id = my_peer_id_;
  initial_alive.info_string = my_info_string_;
  if (interface_manager_->send_on_all_interfaces(initial_alive)) {
    last_broadcast_time_ = std::chrono::steady_clock::now();
    LOG("Sent initial broadcast");
  }

  // Start timers
  broadcast_timer_.start(std::chrono::milliseconds(NOMINAL_BROADCAST_INTERVAL_MS), [this]()
                         { broadcast_alive(); });

  cleanup_timer_.start(std::chrono::milliseconds(PEER_CLEANUP_INTERVAL_MS), [this]()
                       { cleanup_peers(); });

  LOG("Discovery service started successfully");
  return true;
}

void DiscoveryService::stop()
{
  if (!running_.load())
    return;

  LOG("Stopping discovery service...");

  // Send bye-bye messages
  Message byebye;
  byebye.type = MSG_BYEBYE;
  byebye.peer_id = my_peer_id_;
  byebye.info_string = my_info_string_;

  interface_manager_->send_on_all_interfaces(byebye);

  running_.store(false);

  // Stop timers
  broadcast_timer_.stop();
  cleanup_timer_.stop();

  // Stop interface management
  interface_manager_->stop_all();

  LOG("Discovery service stopped");
}

std::vector<PeerInfo> DiscoveryService::get_peers() const
{
  return peer_manager_->get_all_peers();
}

// ENHANCED: Discovery service message handling with improved callback logic
void DiscoveryService::handle_received_message(const Message &msg, const std::string &sender_ip,
                                               const std::string &interface_name, bool is_wired)
{
  if (msg.peer_id == my_peer_id_)
  {
    return; // Ignore messages from ourselves
  }

  LOG("Received " << (msg.type == MSG_ALIVE ? "ALIVE" : msg.type == MSG_RESPONSE ? "RESPONSE"
                                                                                 : "BYEBYE")
                  << " from " << msg.peer_id << " (" << msg.info_string << ") at " << sender_ip << " via " << interface_name);

  bool should_notify = false;

  if (msg.type == MSG_ALIVE)
  {
    auto result = peer_manager_->add_or_update_peer(msg.peer_id, msg.info_string, sender_ip, interface_name, is_wired);

    // Send unicast response message to sender
    Message response;
    response.type = MSG_RESPONSE;
    response.peer_id = my_peer_id_;
    response.info_string = my_info_string_;

    // Feature 2: Use selected endpoint for response
    interface_manager_->send_unicast_on_interface(response, sender_ip, interface_name);

    // Feature 6: Only trigger callback on peer list changes
    should_notify = result.peer_list_changed && notifications_enabled();

    if (should_notify)
    {
      LOG("Triggering callback for ALIVE - peer_list_changed=" << result.peer_list_changed << " total_peers=" << result.total_peers);
    }
  }
  else if (msg.type == MSG_RESPONSE)
  {
    auto result = peer_manager_->add_or_update_peer(msg.peer_id, msg.info_string, sender_ip, interface_name, is_wired);

    // Feature 6: Only trigger callback on peer list changes
    should_notify = result.peer_list_changed && notifications_enabled();

    if (should_notify)
    {
      LOG("Triggering callback for RESPONSE - peer_list_changed=" << result.peer_list_changed << " total_peers=" << result.total_peers);
    }
  }
  else if (msg.type == MSG_BYEBYE)
  {
    bool was_removed = peer_manager_->remove_peer(msg.peer_id);

    should_notify = was_removed && notifications_enabled();

    if (should_notify)
    {
      LOG("Triggering callback for BYEBYE - peer_removed=" << was_removed);
    }
  }

  // ENHANCED: Always call callback if something changed
  if (should_notify)
  {
    LOG("Calling on_peers_changed()");
    on_peers_changed();
  }
}

// Feature 7: Adaptive broadcast timer
void DiscoveryService::broadcast_alive()
{
  if (!running_.load())
    return;

  // Rate limiting like Link
  auto now = std::chrono::steady_clock::now();
  auto time_since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_broadcast_time_);

  // Calculate next broadcast time (adaptive like Link)
  auto min_interval = std::chrono::milliseconds(MIN_BROADCAST_INTERVAL_MS);
  auto nominal_interval = std::chrono::milliseconds(TTL_SECONDS * 1000 / TTL_RATIO);

  // Feature 7: Adaptive timer to avoid drift
  auto delay = time_since_last < min_interval
    ? min_interval - time_since_last
    : nominal_interval;

  // Reschedule next broadcast (safe from within callback)
  broadcast_timer_.reschedule(delay);

  // Only broadcast if enough time has passed (rate limiting)
  if (time_since_last >= min_interval)
  {
    Message alive;
    alive.type = MSG_ALIVE;
    alive.peer_id = my_peer_id_;
    alive.info_string = my_info_string_;

    if (interface_manager_->send_on_all_interfaces(alive))
    {
      last_broadcast_time_ = now;
      LOG("Broadcasted alive message");
    }
  }
}

// ENHANCED: Cleanup peers with better callback handling
void DiscoveryService::cleanup_peers()
{
  if (!running_.load())
    return;

  size_t removed = peer_manager_->cleanup_expired_peers();

  if (removed > 0)
  {
    LOG("Cleaned up " << removed << " expired peers");
    if (notifications_enabled())
    {
      LOG("Calling on_peers_changed() after cleanup");
      on_peers_changed();
    }
  }
}

// External API implementation
void start_discovery_impl(const char *info_string)
{
  std::lock_guard<std::mutex> lock(g_service_mutex);

  if (!g_service)
  {
    g_service = std::make_unique<DiscoveryService>();
  }

  g_service->start(info_string ? info_string : "");
}

void stop_discovery_impl()
{
  std::lock_guard<std::mutex> lock(g_service_mutex);

  if (g_service)
  {
    g_service->stop();
    g_service.reset();
  }
}

ERL_NIF_TERM list_peers_impl(ErlNifEnv *env)
{
  std::lock_guard<std::mutex> lock(g_service_mutex);

  if (!g_service)
  {
    return enif_make_list(env, 0);
  }

  auto peers = g_service->get_peers();
  std::vector<ERL_NIF_TERM> peer_terms;
  peer_terms.reserve(peers.size());

  for (const auto &peer : peers)
  {
    ErlNifBinary info_bin;
    enif_alloc_binary(static_cast<unsigned int>(peer.info_string.length()), &info_bin);
    memcpy(info_bin.data, peer.info_string.c_str(), peer.info_string.length());

    ERL_NIF_TERM peer_term = enif_make_tuple4(env,
                                              enif_make_string(env, peer.peer_id.c_str(), ERL_NIF_LATIN1),
                                              enif_make_binary(env, &info_bin),
                                              enif_make_string(env, peer.ip_address.c_str(), ERL_NIF_LATIN1),
                                              enif_make_string(env, peer.interface_name.c_str(), ERL_NIF_LATIN1));

    peer_terms.push_back(peer_term);
  }

  return enif_make_list_from_array(env, peer_terms.data(), peer_terms.size());
}

void enable_nif_logging_impl()
{
  g_logging_enabled.store(true);
  LOG("Logging enabled");
}

void disable_nif_logging_impl()
{
  LOG("Logging disabled");
  g_logging_enabled.store(false);
}

bool is_nif_logging_enabled_impl()
{
  return g_logging_enabled.load();
}