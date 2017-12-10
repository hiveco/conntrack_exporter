#include "connection_table.h"

#include <cassert>
#include <fcntl.h>
#include <iostream>


namespace conntrackex {

using namespace std;

ConnectionTable::ConnectionTable()
{
    this->handle = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!this->handle)
        throw runtime_error("Unable to open NetFilter socket. (Does the current user have sufficient privileges?)");
}

ConnectionTable::~ConnectionTable()
{
    nfct_close(this->handle);
}

void ConnectionTable::attach()
{
    // Switch the netfilter socket to non-blocking to prevent nfct_catch from
    // taking control. See https://www.spinics.net/lists/netfilter-devel/msg20952.html
    int fd = nfct_fd(this->handle);
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) != 0)
        assert(false);

    this->rebuild();

    nfct_callback_register(this->handle, NFCT_T_ALL, ConnectionTable::nfct_callback, this);
}

void ConnectionTable::update()
{
    nfct_catch(this->handle);
}

void ConnectionTable::rebuild()
{
    this->connections.clear();

    nfct_callback_register(this->handle, NFCT_T_ALL, ConnectionTable::nfct_callback, this);

    this->is_rebuilding = true;

    uint32_t family = AF_INET;
    nfct_query(this->handle, NFCT_Q_DUMP, &family);

    this->is_rebuilding = false;
}

void ConnectionTable::updateConnection(Connection& connection)
{
    // When rebuilding, we should never get a connection that is untracked (i.e.
    // no longer being tracked by the kernel):
    assert(!(this->is_rebuilding && connection.hasTrackingStopped()));

    pair<ConnectionSet::iterator, bool> result = this->connections.insert(connection);
    if (!result.second)
    {
        auto& old_connection = *result.first;

        if (!connection.hasTrackingStopped())
            connection.mergeStateHistory(old_connection);

        ConnectionSet::iterator hint = result.first;
        hint++;
        this->connections.erase(result.first);

        if (!connection.hasTrackingStopped())
            this->connections.insert(hint, connection);
    }

    // DEBUG
    if (this->log_events)
    {
        int tcp_state = nfct_get_attr_u8(connection.conntrack, ATTR_TCP_STATE);
        string event = result.second ? "NEW" : "UPDATE";
        cout << event << " ["
            << "id=" << to_string(nfct_get_attr_u32(connection.conntrack, ATTR_ID))
            << ", tcp_state=" << to_string(tcp_state)
            << ", num_states=" << to_string(connection.getStateHistory().size())
            << ", table_size=" << this->connections.size()
            << "]" << endl;
    }
    // DEBUG
}

int ConnectionTable::nfct_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    auto table = static_cast<ConnectionTable*>(data);

    if (!Connection::isConnTrackSupported(ct))
        return NFCT_CB_CONTINUE;

    if (table->log_events)
    {
        char buf[1024];
        nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_TIME | NFCT_OF_TIMESTAMP | NFCT_OF_SHOW_LAYER3);
        printf("%s\n", buf);
    }

    auto connection = new Connection(ct);
    table->updateConnection(*connection);

    return NFCT_CB_CONTINUE;
}

} // namespace conntrackex
