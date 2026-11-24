/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>
#include <stddef.h>
#include <stdint.h>

class WireGuard
{
private:
    bool _is_initialized = false;

public:
    bool begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey = NULL);
    bool begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey = NULL);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
    bool is_peer_up(char *endpoint_ip_buf = NULL, size_t endpoint_ip_buf_len = 0, uint16_t *endpoint_port = NULL) const;
};
