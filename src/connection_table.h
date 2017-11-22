#pragma once

#include <set>

#include "connection.h"


namespace conntrackex {

class ConnectionTable
{
public:

    void rebuild();
    std::set<Connection>& getConnections() { return this->connections; }

private:

    static int nfct_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);

    std::set<Connection> connections;
};

} // namespace conntrackex
