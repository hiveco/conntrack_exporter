#pragma once

#include <set>

#include "connection.h"


namespace conntrackex {

using namespace std;

typedef set<Connection> ConnectionSet;

class ConnectionTable
{
public:

    ConnectionTable();
    ~ConnectionTable();

    void enableLogging(bool enable = true) { this->log_events = enable; }
    void enableDebugging(bool enable = true) { this->debugging = enable; }

    void attach();
    void update();

    ConnectionSet& getConnections() { return this->connections; }

private:

    static int nfct_callback_attach(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);
    static int nfct_callback_rebuild(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);

    void rebuild();
    void updateConnection(enum nf_conntrack_msg_type type, Connection& connection);

    nfct_handle* handle;
    bool is_rebuilding;
    bool log_events = false;
    bool debugging = false;
    ConnectionSet connections;
};

} // namespace conntrackex
