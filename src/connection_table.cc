#include "connection_table.h"

#include <cassert>
#include <thread>


namespace conntrackex {

using namespace std;

ConnectionTable::ConnectionTable()
{
    this->handle = nfct_open(CONNTRACK, 0);
    assert(this->handle);
}

ConnectionTable::~ConnectionTable()
{
    nfct_close(this->handle);
}

void ConnectionTable::rebuild()
{
    this->connections.clear();

    nfct_callback_register(this->handle, NFCT_T_ALL, ConnectionTable::nfct_rebuild_callback, this);

    uint32_t family = AF_INET;
    nfct_query(this->handle, NFCT_Q_DUMP, &family);
}

int ConnectionTable::nfct_rebuild_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
{
    auto table = static_cast<ConnectionTable*>(data);

    if (!Connection::isConnTrackSupported(ct))
        return NFCT_CB_CONTINUE;

    /* DEBUG
    char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_TIME | NFCT_OF_TIMESTAMP | NFCT_OF_SHOW_LAYER3);
    printf("%s\n", buf);
      DEBUG */

    auto ci = new Connection(ct);
    table->connections.insert(*ci);

    return NFCT_CB_CONTINUE;
}

} // namespace conntrackex
