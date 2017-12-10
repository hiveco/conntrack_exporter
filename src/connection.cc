#include "connection.h"

#include <cassert>


namespace conntrackex {

using namespace std;

bool Connection::isConnTrackSupported(nf_conntrack* ct)
{
    // We only want TCP connections:
    if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != IPPROTO_TCP)
        return false;

    return true;
}

Connection::Connection(nf_conntrack* ct)
{
    this->conntrack = nfct_clone(ct);

    if (!this->hasTrackingStopped())
        this->state_history.push_front(this->getState());
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

bool Connection::hasTrackingStopped() const
{
    // ATTR_TCP_STATE == TCP_CONNTRACK_NONE is not a real TCP state, and is
    // used by libnetfilter_conntrack as a flag to indicate that this conntrack
    // is being dropped from the kernel's tables.

    return (nfct_get_attr_u8(this->conntrack, ATTR_TCP_STATE) == TCP_CONNTRACK_NONE);
}

ConnectionState Connection::getState() const
{
    auto tcp_state = nfct_get_attr_u8(this->conntrack, ATTR_TCP_STATE);

    // Calling this method on an untracked connection is a bug. We also don't
    // expect to see MAX or IGNORE.
    assert(!this->hasTrackingStopped() &&
           tcp_state != TCP_CONNTRACK_MAX &&
           tcp_state != TCP_CONNTRACK_IGNORE);

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

void Connection::mergeStateHistory(const Connection& previous)
{
    // If the previous connection has the same state as this connection, then
    // there's nothing to do. This occurs when there is a change in TCP state
    // that we still consider the same state. Since state changes are always
    // in the order OPENING > OPEN > CLOSING > CLOSED, we just need to check
    // if the current states are the same.
    if (previous.getState() == this->getState())
        return;

    // We'll be clearing the history, so make sure it's empty or only contains
    // the current state:
    assert(this->state_history.size() < 2);
    this->state_history.clear();

    // Merge the previous historical states and the current state:
    this->state_history = previous.state_history;
    this->state_history.push_front(this->getState());
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
    }

    assert(false);
    return "";
}

} // namespace conntrackex
