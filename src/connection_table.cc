#include "connection_table.h"


namespace conntrackex {

using namespace std;

void ConnectionTable::rebuild()
{
    this->connections.clear();

    auto handle = nfct_open(CONNTRACK, 0);
    if (!handle)
        return;

    nfct_callback_register(handle, NFCT_T_ALL, ConnectionTable::nfct_callback, this);

    uint32_t family = AF_INET;
    nfct_query(handle, NFCT_Q_DUMP, &family);

    nfct_close(handle);
}

int ConnectionTable::nfct_callback(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data)
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
