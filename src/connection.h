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
    ~Connection();

    string getRemoteIP() const;
    uint16_t getRemotePort() const;
    string getRemoteHost() const { return this->getRemoteIP() + ":" + std::to_string(this->getRemotePort()); }
    ConnectionState getState() const;
    string getStateString() const { return stateToString(this->getState()); }
    string toString() const;

    bool operator<(const Connection& other) const;
    bool operator==(const Connection& other) const;

private:

    static string ip32ToString(uint32_t ip32);
    static string stateToString(ConnectionState state);

    nf_conntrack* conntrack;
};

} // namespace conntrackex
