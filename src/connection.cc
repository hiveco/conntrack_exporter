#include "connection.h"


namespace conntrackex {

using namespace std;

bool Connection::isConnTrackSupported(nf_conntrack* ct)
{
    if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != IPPROTO_TCP)
        return false;

    return true;
}

Connection::Connection(nf_conntrack* ct)
{
    this->conntrack = nfct_clone(ct);
}

Connection::~Connection()
{
    nfct_destroy(this->conntrack);
    this->conntrack = NULL;
}

string Connection::getRemoteIP() const
{
    // Alternative: ATTR_ORIG_IPV4_DST
    return ip32ToString(nfct_get_attr_u32(this->conntrack, ATTR_ORIG_IPV4_SRC));
}

uint16_t Connection::getRemotePort() const
{
    // Alternative: ATTR_REPL_PORT_SRC
    return ntohs(nfct_get_attr_u16(this->conntrack, ATTR_ORIG_PORT_DST));
}

ConnectionState Connection::getState() const
{
    switch (nfct_get_attr_u8(this->conntrack, ATTR_TCP_STATE))
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
        case TCP_CONNTRACK_NONE:
        case TCP_CONNTRACK_MAX:
        case TCP_CONNTRACK_IGNORE:
            break;
    }

    return ConnectionState::CLOSED;
}

string Connection::toString() const
{
    stringstream output;
    output
        << "{"
        << "\"remote_host\":\"" << this->getRemoteIP().c_str() << ":" << this->getRemotePort() << "\","
        << "\"state\":\"" << this->getStateString().c_str() << "\""
        << "}";
    return output.str();
}

bool Connection::operator<(const Connection& other) const
{
    return (nfct_get_attr_u32(this->conntrack, ATTR_ID) < nfct_get_attr_u32(other.conntrack, ATTR_ID));
}

bool Connection::operator==(const Connection& other) const
{
    return (nfct_compare(this->conntrack, other.conntrack) == 1);
}

string Connection::ip32ToString(uint32_t ip32)
{
    char output[INET_ADDRSTRLEN];

    return (inet_ntop(AF_INET, (void*)&ip32, output, INET_ADDRSTRLEN) != NULL) ?
        string((char*)&output) :
        string("");
}

string Connection::stateToString(ConnectionState state)
{
    switch (state)
    {
        case ConnectionState::OPENING: return "Opening";
        case ConnectionState::OPEN: return "Open";
        case ConnectionState::CLOSING: return "Closing";
        case ConnectionState::CLOSED: return "Closed";
        default: return "";
    }
}

} // namespace conntrackex
