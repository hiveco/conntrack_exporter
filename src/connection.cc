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
    this->id = nfct_get_attr_u32(ct, ATTR_ID);
    this->state = getStateFromTCPState(nfct_get_attr_u8(ct, ATTR_TCP_STATE));
    this->remote_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    this->remote_port = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
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

ConnectionState Connection::getStateFromTCPState(uint8_t tcp_state)
{
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
        case TCP_CONNTRACK_NONE:
        case TCP_CONNTRACK_MAX:
        case TCP_CONNTRACK_IGNORE:
        default:
            return ConnectionState::CLOSED;
    }
}

} // namespace conntrackex
