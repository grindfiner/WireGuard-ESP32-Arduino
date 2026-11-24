/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/netif.h"

#include "esp32-hal-log.h"

extern "C"
{
#include "wireguardif.h"
#include "wireguard-platform.h"
}

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static struct netif *previous_default_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

#define TAG "[WireGuard] "

namespace
{
struct WgBeginCtx
{
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gateway;
    struct wireguardif_init_data wg;
    struct wireguardif_peer peer;
};

struct WgPeerStatusCtx
{
    ip_addr_t current_ip;
    uint16_t current_port;
    bool is_up;
};

struct WgIpv6CheckCtx
{
    bool has_usable_ipv6;
    struct netif *preferred_netif;
};

esp_err_t check_ipv6_available_cb(void *ctx)
{
    WgIpv6CheckCtx *out = static_cast<WgIpv6CheckCtx *>(ctx);
    out->has_usable_ipv6 = false;
    out->preferred_netif = netif_default;
#if LWIP_IPV6
    struct netif *n = NULL;
    NETIF_FOREACH(n)
    {
        if (n == wg_netif || !netif_is_up(n) || !netif_is_link_up(n))
            continue;
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(n, i)) &&
                !ip6_addr_islinklocal(netif_ip6_addr(n, i)) &&
                !ip6_addr_isloopback(netif_ip6_addr(n, i)))
            {
                out->has_usable_ipv6 = true;
                out->preferred_netif = n;
                return ESP_OK;
            }
        }
    }
#endif
    return ESP_OK;
}

bool resolve_endpoint_ip(const char *remotePeerAddress, ip_addr_t *endpoint_ip)
{
    char clean_host[256];
    size_t host_len = strlen(remotePeerAddress);
    if (host_len >= 2 && remotePeerAddress[0] == '[' && remotePeerAddress[host_len - 1] == ']')
    {
        size_t copy_len = host_len - 2;
        if (copy_len >= sizeof(clean_host))
            copy_len = sizeof(clean_host) - 1;
        memcpy(clean_host, remotePeerAddress + 1, copy_len);
        clean_host[copy_len] = '\0';
    }
    else
    {
        strncpy(clean_host, remotePeerAddress, sizeof(clean_host) - 1);
        clean_host[sizeof(clean_host) - 1] = '\0';
    }

    WgIpv6CheckCtx ipv6_ctx = {};
    esp_netif_tcpip_exec(check_ipv6_available_cb, &ipv6_ctx);

    // lwIP's AF_UNSPEC resolves IPv4 first and skips AAAA if an A record exists (breaking CGNAT dual-stack DDNS).
    // Explicitly query AF_INET6 first whenever a non-link-local IPv6 address is active on the device.
    const int families[2] = {
        ipv6_ctx.has_usable_ipv6 ? AF_INET6 : AF_INET,
        ipv6_ctx.has_usable_ipv6 ? AF_INET : AF_INET6
    };

    for (int i = 0; i < 2; i++)
    {
        struct addrinfo hint;
        struct addrinfo *res = NULL;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = families[i];
        hint.ai_socktype = SOCK_DGRAM;

        if (lwip_getaddrinfo(clean_host, NULL, &hint, &res) != 0 || res == NULL)
            continue;

        bool converted = false;
#if LWIP_IPV6
        if (res->ai_family == AF_INET6 && res->ai_addrlen >= sizeof(struct sockaddr_in6))
        {
            struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(res->ai_addr);
            inet6_addr_to_ip6addr(ip_2_ip6(endpoint_ip), &sa6->sin6_addr);
            IP_SET_TYPE_VAL(*endpoint_ip, IPADDR_TYPE_V6);
            if (ipv6_ctx.preferred_netif != NULL && ip6_addr_has_scope(ip_2_ip6(endpoint_ip), IP6_UNICAST))
            {
                ip6_addr_assign_zone(ip_2_ip6(endpoint_ip), IP6_UNICAST, ipv6_ctx.preferred_netif);
            }
            converted = true;
        }
        else
#endif
        if (res->ai_family == AF_INET && res->ai_addrlen >= sizeof(struct sockaddr_in))
        {
            struct sockaddr_in *sa4 = reinterpret_cast<struct sockaddr_in *>(res->ai_addr);
            inet_addr_to_ip4addr(ip_2_ip4(endpoint_ip), &sa4->sin_addr);
            IP_SET_TYPE_VAL(*endpoint_ip, IPADDR_TYPE_V4);
            ip_clear_no4(endpoint_ip);
            converted = true;
        }

        lwip_freeaddrinfo(res);
        if (converted)
            return true;
    }

    return false;
}

esp_err_t wg_begin_tcpip_cb(void *arg)
{
    WgBeginCtx *ctx = static_cast<WgBeginCtx *>(arg);

    memset(&wg_netif_struct, 0, sizeof(wg_netif_struct));
    wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ctx->ipaddr), ip_2_ip4(&ctx->netmask), ip_2_ip4(&ctx->gateway), &ctx->wg, &wireguardif_init, &ip_input);
    if (wg_netif == nullptr)
    {
        log_e(TAG "failed to initialize WG netif.");
        return ESP_FAIL;
    }
    netif_set_up(wg_netif);

    wireguardif_add_peer(wg_netif, &ctx->peer, &wireguard_peer_index);
    if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&ctx->peer.endpoint_ip))
    {
        log_i(TAG "connecting wireguard...");
        wireguardif_connect(wg_netif, wireguard_peer_index);
        previous_default_netif = netif_default;
        netif_set_default(wg_netif);
    }
    return ESP_OK;
}

esp_err_t wg_end_tcpip_cb(void *arg)
{
    (void)arg;
    if (wg_netif == nullptr)
        return ESP_OK;

    netif_set_default(previous_default_netif);
    previous_default_netif = nullptr;
    wireguardif_disconnect(wg_netif, wireguard_peer_index);
    wireguardif_remove_peer(wg_netif, wireguard_peer_index);
    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    wireguardif_shutdown(wg_netif);
    netif_remove(wg_netif);
    wg_netif = nullptr;
    return ESP_OK;
}

esp_err_t wg_peer_status_tcpip_cb(void *arg)
{
    WgPeerStatusCtx *ctx = static_cast<WgPeerStatusCtx *>(arg);
    ctx->is_up = false;
    if (wg_netif == nullptr || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX)
        return ESP_OK;

    err_t err = wireguardif_peer_is_up(wg_netif, wireguard_peer_index, &ctx->current_ip, &ctx->current_port);
    ctx->is_up = (err == ERR_OK);
    return ESP_OK;
}
} // namespace

bool WireGuard::begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey)
{
    assert(privateKey != NULL);
    assert(remotePeerAddress != NULL);
    assert(remotePeerPublicKey != NULL);
    assert(remotePeerPort != 0);

    if (this->_is_initialized)
    {
        this->end();
    }

    WgBeginCtx ctx = {};
    ctx.ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
    ctx.netmask = IPADDR4_INIT(static_cast<uint32_t>(Subnet));
    ctx.gateway = IPADDR4_INIT(static_cast<uint32_t>(Gateway));

    ctx.wg.private_key = privateKey;
    ctx.wg.listen_port = remotePeerPort;
    ctx.wg.bind_netif = NULL;

    wireguardif_peer_init(&ctx.peer);

    bool success_get_endpoint_ip = false;
    for (int retry = 0; retry < 5; retry++)
    {
        ip_addr_t endpoint_ip = {};
        if (!resolve_endpoint_ip(remotePeerAddress, &endpoint_ip))
        {
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        success_get_endpoint_ip = true;
        ctx.peer.endpoint_ip = endpoint_ip;

        char ip_str[IPADDR_STRLEN_MAX];
        ipaddr_ntoa_r(&endpoint_ip, ip_str, sizeof(ip_str));
        log_i(TAG "%s resolved to %s (%s)", remotePeerAddress, ip_str, IP_IS_V6(&endpoint_ip) ? "IPv6" : "IPv4");
        break;
    }
    if (!success_get_endpoint_ip)
    {
        log_e(TAG "failed to get endpoint ip.");
        return false;
    }

    ctx.peer.public_key = remotePeerPublicKey;
    ctx.peer.preshared_key = presharedKey;

    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    ctx.peer.allowed_ip = allowed_ip;
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    ctx.peer.allowed_mask = allowed_mask;
    ctx.peer.endport_port = remotePeerPort;

    wireguard_platform_init();

    if (esp_netif_tcpip_exec(wg_begin_tcpip_cb, &ctx) != ESP_OK)
    {
        return false;
    }

    this->_is_initialized = true;
    return true;
}

bool WireGuard::begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey)
{
    auto subnet = IPAddress(255, 255, 255, 255);
    auto gateway = IPAddress(0, 0, 0, 0);
    return WireGuard::begin(localIP, subnet, gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, presharedKey);
}

void WireGuard::end()
{
    if (!this->_is_initialized)
        return;

    esp_netif_tcpip_exec(wg_end_tcpip_cb, nullptr);
    this->_is_initialized = false;
}

bool WireGuard::is_peer_up(char *endpoint_ip_buf, size_t endpoint_ip_buf_len, uint16_t *endpoint_port) const
{
    if (!this->_is_initialized)
        return false;

    WgPeerStatusCtx ctx = {};
    if (esp_netif_tcpip_exec(wg_peer_status_tcpip_cb, &ctx) != ESP_OK)
        return false;

    if (endpoint_ip_buf != NULL && endpoint_ip_buf_len > 0)
    {
        ipaddr_ntoa_r(&ctx.current_ip, endpoint_ip_buf, static_cast<int>(endpoint_ip_buf_len));
    }
    if (endpoint_port != NULL)
    {
        *endpoint_port = ctx.current_port;
    }
    return ctx.is_up;
}
