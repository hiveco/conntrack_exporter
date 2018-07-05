#include "connection_table.h"

#include <fcntl.h>
#include <iostream>
#include <algorithm>


namespace conntrackex {

using namespace std;

ConnectionTable::ConnectionTable()
{
    this->attach_handle = makeConntrackHandle();
    this->rebuild_handle = makeConntrackHandle();
}

ConnectionTable::~ConnectionTable()
{
    nfct_close(this->attach_handle);
    nfct_close(this->rebuild_handle);
}

nfct_handle* ConnectionTable::makeConntrackHandle()
{
    uint32_t family = AF_INET;

    // HACK: Initialize conntrack; see https://github.com/markusa/netsniff-ng_filter/blob/master/src/flowtop.c#L850-L861
    auto dummy_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, NFCT_ALL_CT_GROUPS);
    if (!dummy_handle)
        throw runtime_error("Unable to open NetFilter socket. (Does the current user have sufficient privileges?)");
    nfct_callback_register(dummy_handle, NFCT_T_ALL, ConnectionTable::nfct_callback_dummy, NULL);
	nfct_query(dummy_handle, NFCT_Q_DUMP, &family);
	nfct_close(dummy_handle);

    auto handle = nfct_open(NFNL_SUBSYS_CTNETLINK, NFCT_ALL_CT_GROUPS);
    if (!handle)
        throw runtime_error("Unable to open NetFilter socket. (Does the current user have sufficient privileges?)");

    nfct_query(handle, NFCT_Q_FLUSH, &family);

    auto filter = nfct_filter_create();
    if (!filter)
        throw runtime_error("Unable to create netfilter_conntrack filter!");

    // Filter in only TCP entries:
    nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);

    if (nfct_filter_attach(nfct_fd(handle), filter) < 0)
		throw runtime_error("Unable to attach netfilter_conntrack filter to handle!");

	nfct_filter_destroy(filter);

    return handle;
}

void ConnectionTable::attach()
{
    // Switch the netfilter socket to non-blocking to prevent nfct_catch from
    // taking control. See https://www.spinics.net/lists/netfilter-devel/msg20952.html
    int fd = nfct_fd(this->attach_handle);
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) != 0)
        throw runtime_error("Error setting the NetFilter socket to non-blocking mode.");

    this->rebuild();

    nfct_callback_register(this->attach_handle, NFCT_T_ALL, ConnectionTable::nfct_callback_attach, this);
}

void ConnectionTable::update()
{
    nfct_catch(this->attach_handle);
}

void ConnectionTable::rebuild()
{
    this->connections.clear();

    nfct_callback_register(this->rebuild_handle, NFCT_T_ALL, ConnectionTable::nfct_callback_rebuild, this);

    this->is_rebuilding = true;
    if (this->debugging)
        cout << "[DEBUG] Rebuilding connection table" << endl;

    uint32_t family = AF_INET;
    nfct_query(this->rebuild_handle, NFCT_Q_DUMP, &family);

    this->is_rebuilding = false;
    if (this->debugging)
        cout << "[DEBUG] Finished rebuilding connection table" << endl;
}

bool ConnectionTable::isIgnoredHost(const string& host) const
{
    return (find(this->ignored_hosts.begin(),
                 this->ignored_hosts.end(),
                 host) != this->ignored_hosts.end());
}

int ConnectionTable::nfct_callback_attach(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    Connection connection(ct);
    auto table = static_cast<ConnectionTable*>(data);
    table->updateConnection(type, connection);

    return NFCT_CB_CONTINUE;
}

int ConnectionTable::nfct_callback_rebuild(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    if (type == NFCT_T_UPDATE)
        type = NFCT_T_NEW;

    Connection connection(ct);
    auto table = static_cast<ConnectionTable*>(data);
    table->updateConnection(type, connection);

    return NFCT_CB_CONTINUE;
}

void ConnectionTable::updateConnection(enum nf_conntrack_msg_type type, Connection& connection)
{
    connection.setEventType(type);

    if (this->isIgnoredHost(connection.getRemoteHost()))
    {
        if (this->debugging)
        {
            cout << "[DEBUG] Remote host is present on the ignore list, ignoring connection:" << endl;
            cout << "\t" << connection.toNetFilterString() << endl;
        }
        return;
    }

    // Log the event:
    if (this->log_events && !this->is_rebuilding)
    {
        if (this->log_events_format == "netfilter")
            cout << connection.toNetFilterString() << endl;
        else
            cout << connection.toString() << endl;
    }

    // If we can find an existing connection in our table that matches the
    // incoming one, delete it:
    auto old_connection_it = find(this->connections.begin(), this->connections.end(), connection);
    bool exists = (old_connection_it != this->connections.end());
    if (exists)
    {
        if (this->debugging)
        {
            cout << "[DEBUG] Deleting an existing connection in the table matching the one from the current event:" << endl;
            cout << "\t" << (*old_connection_it).toNetFilterString() << endl;
        }

        this->connections.erase(old_connection_it);
    }

    switch (type)
    {
        case NFCT_T_NEW:
        case NFCT_T_UPDATE:
        {
            if (this->debugging)
            {
                if (type == NFCT_T_NEW)
                {
                    if (exists)
                    {
                        cout << "[DEBUG] WARNING: Current connection was supposed to be new but it matched an existing one in our table (rebuilding="
                             << (this->is_rebuilding ? "true" : "false")
                             << "):" << endl;
                        cout << "\t" << connection.toNetFilterString() << endl;
                    }
                }
                else
                {
                    if (!exists)
                    {
                        cout << "[DEBUG] WARNING: Tried to update an existing connection in our table but a match was not found (rebuilding="
                            << (this->is_rebuilding ? "true" : "false")
                            << "):" << endl;
                        cout << "\t" << connection.toNetFilterString() << endl;
                    }
                }
            }

            this->connections.push_back(connection);

            break;
        }

        case NFCT_T_DESTROY:
        {
            if (this->debugging)
            {
                if (!exists)
                {
                    cout << "[DEBUG] WARNING: Tried to delete an existing connection in our table but a match was not found (rebuilding="
                        << (this->is_rebuilding ? "true" : "false")
                        << "):" << endl;
                    cout << "\t" << connection.toNetFilterString() << endl;
                }
            }
            break;
        }

        default:
            break;
    }
}

} // namespace conntrackex
