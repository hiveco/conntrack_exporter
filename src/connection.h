#pragma once

#include <string>
#include <list>
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

    Connection(nf_conntrack* ct);
    Connection(const Connection &other);
    ~Connection();

    static void loadLocalIPAddresses(bool log_debug_messages = false);

    string getOriginalSourceIP() const;
    uint16_t getOriginalSourcePort() const;
    string getOriginalSourceHost() const { return this->getOriginalSourceIP() + ":" + to_string(this->getOriginalSourcePort()); }
    string getOriginalDestinationIP() const;
    uint16_t getOriginalDestinationPort() const;
    string getOriginalDestinationHost() const { return this->getOriginalDestinationIP() + ":" + to_string(this->getOriginalDestinationPort()); }
    string getReplySourceIP() const;
    uint16_t getReplySourcePort() const;
    string getReplySourceHost() const { return this->getReplySourceIP() + ":" + to_string(this->getReplySourcePort()); }
    string getReplyDestinationIP() const;
    uint16_t getReplyDestinationPort() const;
    string getReplyDestinationHost() const { return this->getReplyDestinationIP() + ":" + to_string(this->getReplyDestinationPort()); }

    string getRemoteHost() const;

    bool hasState() const;
    ConnectionState getState() const;
    string getStateString() const { return stateToString(this->getState()); }

    void setEventType(nf_conntrack_msg_type type) { this->event_type = type; }
    string toString() const;
    string toNetFilterString() const;

    bool operator==(const Connection& other) const;

private:

    static string ip32ToString(uint32_t ip32);
    static string stateToString(const ConnectionState state);
    bool hasEventType() const { return this->event_type != NFCT_T_UNKNOWN; }
    const string getEventTypeString() const;

    static bool isLocalIPAddress(const string& ip_address);
    static list<string> local_ip_addresses;

    nf_conntrack* conntrack;
    nf_conntrack_msg_type event_type = NFCT_T_UNKNOWN;
};

} // namespace conntrackex
