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
        throw runtime_error("Error setting the NetFilter socket to non-blocking mode.");

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
    if (this->is_rebuilding && !connection.isTracked())
        throw logic_error("Found a NOTRACK connection when rebuilding the connection table.");

    // TODO: The above exception might occur if an event from attach() happens
    // during a rebuild(). Refactor nfct_callback() into two separate callbacks
    // each of which calls a different version of this updateConnection()
    // method to avoid the issue.

    pair<ConnectionSet::iterator, bool> result = this->connections.insert(connection);

    // If the connection was not already in the table, there's nothing else to
    // do. However, if the connection is not tracked then we actually want to
    // undo the insertion above (netfilter_conntrack is likely telling us about
    // a NOTRACK connection, which is safe to ignore), so we don't return just
    // yet.
    if (result.second && connection.isTracked())
        return;

    // Erase the existing entry for this connection in the table:
    ConnectionSet::iterator hint = result.first;
    hint++;
    this->connections.erase(result.first);

    // If we are being notified that the current connection is no longer being
    // tracked by the kernel, there's no need to re-add it to the table so
    // we're done:
    if (!connection.isTracked())
        return;

    // Re-insert the up-to-date connection:
    this->connections.insert(hint, connection);
}

int ConnectionTable::nfct_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    auto table = static_cast<ConnectionTable*>(data);

    if (!Connection::isConnTrackSupported(ct))
        return NFCT_CB_CONTINUE;

    if (table->log_events)
    {
        char buf[1024];
        nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_ALL, NFCT_O_DEFAULT, NFCT_OF_TIME | NFCT_OF_TIMESTAMP | NFCT_OF_SHOW_LAYER3);
        printf("%s\n", buf);
    }

    auto connection = new Connection(ct);
    table->updateConnection(*connection);

    return NFCT_CB_CONTINUE;
}

} // namespace conntrackex
