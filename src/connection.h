#pragma once

#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>


namespace conntrackex {

using namespace std;

enum class ConnectionState : unsigned char
{
    OPENING,
    OPEN,
    CLOSING,
    CLOSED
};

class Connection
{
public:

    static bool isConnTrackSupported(nf_conntrack* ct);

    Connection(nf_conntrack* ct);

    uint32_t getID() const { return this->id; }
    string getRemoteIP() const { return ip32ToString(this->remote_ip); }
    uint16_t getRemotePort() const { return this->remote_port; }
    ConnectionState getState() const { return this->state; }
    string getStateString() const { return stateToString(this->state); }
    string getRemoteHost() const { return this->getRemoteIP() + ":" + std::to_string(this->getRemotePort()); }
    string toString() const;

    bool operator< (const Connection& other) const { return (this->id < other.id); }

private:

    static string ip32ToString(uint32_t ip32);
    static string stateToString(ConnectionState state);
    static ConnectionState getStateFromTCPState(uint8_t tcp_state);

    uint32_t id;
    uint32_t remote_ip;
    uint16_t remote_port;
    ConnectionState state;
    time_t last_updated;
};

} // namespace conntrackex
