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

    nfct_callback_register(this->handle, NFCT_T_ALL, ConnectionTable::nfct_callback_attach, this);
}

void ConnectionTable::update()
{
    nfct_catch(this->handle);
}

void ConnectionTable::rebuild()
{
    this->connections.clear();

    nfct_callback_register(this->handle, NFCT_T_ALL, ConnectionTable::nfct_callback_rebuild, this);

    this->is_rebuilding = true;

    uint32_t family = AF_INET;
    nfct_query(this->handle, NFCT_Q_DUMP, &family);

    this->is_rebuilding = false;
}

int ConnectionTable::nfct_callback_attach(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    if (!Connection::isConnTrackSupported(ct))
        return NFCT_CB_CONTINUE;

    auto connection = new Connection(ct);
    auto table = static_cast<ConnectionTable*>(data);
    table->updateConnection(type, *connection);

    return NFCT_CB_CONTINUE;
}

int ConnectionTable::nfct_callback_rebuild(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    if (!Connection::isConnTrackSupported(ct))
        return NFCT_CB_CONTINUE;

    if (type == NFCT_T_UPDATE)
        type = NFCT_T_NEW;

    auto connection = new Connection(ct);
    auto table = static_cast<ConnectionTable*>(data);
    table->updateConnection(type, *connection);

    return NFCT_CB_CONTINUE;
}

void ConnectionTable::updateConnection(enum nf_conntrack_msg_type type, Connection& connection)
{
    if (this->log_events)
        cout << connection.toNetFilterString() << endl;

    pair<ConnectionSet::iterator, bool> result;
    switch (type)
    {
        case NFCT_T_NEW:

            if (this->debugging)
                cout << "[DEBUG] ADD: " << connection.toString() << endl;

            // Fall through...

        case NFCT_T_UPDATE:

            result = this->connections.insert(connection);

            if (type == NFCT_T_UPDATE)
            {
                if (this->debugging)
                    cout << "[DEBUG] UPDATE: " << connection.toString() << endl;

                ConnectionSet::iterator hint = result.first;
                hint++;
                this->connections.erase(result.first);
                this->connections.insert(hint, connection);
            }
            break;

        case NFCT_T_DESTROY:

            if (this->debugging)
                cout << "[DEBUG] REMOVE: " << connection.toString() << endl;

            this->connections.erase(connection);
            break;

        default:
            break;
    }
}

} // namespace conntrackex
