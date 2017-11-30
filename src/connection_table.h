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

    void rebuild();
    ConnectionSet& getConnections() { return this->connections; }

private:

    static int nfct_rebuild_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);

    nfct_handle* handle;
    ConnectionSet connections;
};

} // namespace conntrackex
