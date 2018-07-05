#include "connection.h"

#include <cassert>
#include <sys/types.h>
#include <ifaddrs.h>
#include <algorithm>
#include <iostream>
#include <iomanip>


namespace conntrackex {

using namespace std;

list<string> Connection::local_ip_addresses;

Connection::Connection(nf_conntrack* ct)
{
    this->conntrack = nfct_clone(ct);
}

Connection::Connection(const Connection &other)
{
    this->conntrack = nfct_clone(other.conntrack);
}

Connection::~Connection()
{
    nfct_destroy(this->conntrack);
    this->conntrack = NULL;
}

// Source and destination that initiated the connection:
string Connection::getOriginalSourceIP() const          { return ip32ToString(nfct_get_attr_u32(this->conntrack, ATTR_ORIG_IPV4_SRC    )); }
uint16_t Connection::getOriginalSourcePort() const      { return ntohs(nfct_get_attr_u16(       this->conntrack, ATTR_ORIG_PORT_SRC    )); }
string Connection::getOriginalDestinationIP() const     { return ip32ToString(nfct_get_attr_u32(this->conntrack, ATTR_ORIG_IPV4_DST    )); }
uint16_t Connection::getOriginalDestinationPort() const { return ntohs(nfct_get_attr_u16(       this->conntrack, ATTR_ORIG_PORT_DST    )); }

// Source and destination of the expected (in case of [UNREPLIED]) or actual (in case of [ASSURED]) response:
string Connection::getReplySourceIP() const             { return ip32ToString(nfct_get_attr_u32(this->conntrack, ATTR_REPL_IPV4_SRC    )); }
uint16_t Connection::getReplySourcePort() const         { return ntohs(nfct_get_attr_u16(       this->conntrack, ATTR_REPL_PORT_SRC    )); }
string Connection::getReplyDestinationIP() const        { return ip32ToString(nfct_get_attr_u32(this->conntrack, ATTR_REPL_IPV4_DST    )); }
uint16_t Connection::getReplyDestinationPort() const    { return ntohs(nfct_get_attr_u16(       this->conntrack, ATTR_REPL_PORT_DST    )); }

string Connection::getRemoteHost() const
{
    if (isLocalIPAddress(this->getOriginalSourceIP()))
        return this->getOriginalDestinationHost();
    else if (isLocalIPAddress(this->getOriginalDestinationIP()))
        return this->getOriginalSourceHost();
    else if (isLocalIPAddress(this->getReplySourceIP()))
        return this->getReplyDestinationHost();
    else
    {
        // if (!isLocalIPAddress(this->getReplyDestinationIP()))
        //     cerr << "[WARNING] Couldn't identify a local IP address in a connection." << endl;

        return this->getReplySourceHost();
    }
}

bool Connection::hasState() const
{
    return (nfct_attr_is_set(this->conntrack, ATTR_TCP_STATE) != -1 &&
            nfct_get_attr_u8(this->conntrack, ATTR_TCP_STATE) != TCP_CONNTRACK_NONE);
}

ConnectionState Connection::getState() const
{
    // Calling this method on a connection with no state is a bug:
    if (!this->hasState())
        throw logic_error("Connection state not available.");

    auto tcp_state = nfct_get_attr_u8(this->conntrack, ATTR_TCP_STATE);

    // We don't expect to see MAX or IGNORE.
    assert(tcp_state != TCP_CONNTRACK_MAX);
    assert(tcp_state != TCP_CONNTRACK_IGNORE);

    switch (tcp_state)
    {
        case TCP_CONNTRACK_SYN_SENT:
        case TCP_CONNTRACK_SYN_SENT2:
        case TCP_CONNTRACK_SYN_RECV:
            return ConnectionState::OPENING;
        case TCP_CONNTRACK_ESTABLISHED:
            return ConnectionState::OPEN;
        case TCP_CONNTRACK_FIN_WAIT:
        case TCP_CONNTRACK_CLOSE_WAIT:
        case TCP_CONNTRACK_LAST_ACK:
        case TCP_CONNTRACK_TIME_WAIT:
            return ConnectionState::CLOSING;
        case TCP_CONNTRACK_CLOSE:
            return ConnectionState::CLOSED;
    }

    assert(false);
    return ConnectionState::CLOSED;
}

string Connection::toString() const
{
    stringstream output;
    output << "{";

    if (this->hasEventType())
        output << "\"event_type\":\"" << this->getEventTypeString() << "\",";

    output
        << "\"original_source_host\":\"" << this->getOriginalSourceHost() << "\","
        << "\"original_destination_host\":\"" << this->getOriginalDestinationHost() << "\","
        << "\"reply_source_host\":\"" << this->getReplySourceHost() << "\","
        << "\"reply_destination_host\":\"" << this->getReplyDestinationHost() << "\","
        << "\"remote_host\":\"" << this->getRemoteHost() << "\","
        << "\"state\":\"" << (this->hasState() ? this->getStateString() : "None") << "\""
        << "}";
    return output.str();
}

string Connection::toNetFilterString() const
{
    stringstream output;

    if (this->hasEventType())
        output << "event=" << left << std::setw(10) << this->getEventTypeString() << " ";

    char buffer[1024];
    nfct_snprintf(buffer, sizeof(buffer), this->conntrack, NFCT_T_ALL, NFCT_O_DEFAULT, NFCT_OF_TIME | NFCT_OF_TIMESTAMP | NFCT_OF_SHOW_LAYER3);
    output << buffer;

    return output.str();
}

bool Connection::operator==(const Connection& other) const
{
    return (nfct_cmp(this->conntrack, other.conntrack, NFCT_CMP_ORIG | NFCT_CMP_REPL) == 1);
}

string Connection::ip32ToString(uint32_t ip32)
{
    char output[INET_ADDRSTRLEN];

    return (inet_ntop(AF_INET, (void*)&ip32, output, INET_ADDRSTRLEN) != NULL) ?
        string((char*)&output) :
        string("");
}

string Connection::stateToString(const ConnectionState state)
{
    switch (state)
    {
        case ConnectionState::OPENING: return "Opening";
        case ConnectionState::OPEN: return "Open";
        case ConnectionState::CLOSING: return "Closing";
        case ConnectionState::CLOSED: return "Closed";
    }

    return "";
}

inline const string Connection::getEventTypeString() const
{
    return
        (this->event_type == NFCT_T_NEW) ? "new" :
        (this->event_type == NFCT_T_UPDATE) ? "update" :
        (this->event_type == NFCT_T_DESTROY) ? "destroy" :
        "";
}

void Connection::loadLocalIPAddresses(bool log_debug_messages)
{
    // This method inspired by GetNetworkInterfaceInfos() in
    // https://public.msli.com/lcs/muscle/muscle/util/NetworkUtilityFunctions.cpp

    // Singleton gatekeeper:
    static bool initalized = false;
    if (initalized)
        return;
    initalized = true;

    struct ifaddrs* ifap;
    if (getifaddrs(&ifap) != 0)
    {
        cerr << "[WARNING] Can't get local network interface addresses." << endl;
        return;
    }

    auto current_ifap = ifap;
    while(current_ifap)
    {
        //const string interface_name = current_ifap->ifa_name;
        if (current_ifap->ifa_addr &&
            current_ifap->ifa_addr->sa_family == AF_INET)
        {
            auto ip_address = ((struct sockaddr_in*)current_ifap->ifa_addr)->sin_addr.s_addr;
            auto ip_address_str = ip32ToString(ip_address);
            Connection::local_ip_addresses.push_back(ip_address_str);

            if (log_debug_messages)
                cout << "[DEBUG] Found local IP: " << ip_address_str << endl;
        }

        current_ifap = current_ifap->ifa_next;
    }

    freeifaddrs(ifap);
}

bool Connection::isLocalIPAddress(const string& ip_address)
{
    loadLocalIPAddresses();
    return (find(Connection::local_ip_addresses.begin(),
                 Connection::local_ip_addresses.end(),
                 ip_address) != Connection::local_ip_addresses.end());
}

} // namespace conntrackex
