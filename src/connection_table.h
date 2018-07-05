#pragma once

#include <list>

#include "connection.h"


namespace conntrackex {

using namespace std;

typedef list<Connection> ConnectionList;

class ConnectionTable
{
public:

    ConnectionTable();
    ~ConnectionTable();

    void enableLogging(bool enable = true) { this->log_events = enable; }
    void enableDebugging(bool enable = true) { this->debugging = enable; }
    void setLoggingFormat(string format) { this->log_events_format = format; }
    void addIgnoredHost(const string& host) { this->ignored_hosts.push_back(host); }

    void attach();
    void update();

    const ConnectionList& getConnections() const { return this->connections; }

private:

    nfct_handle* makeConntrackHandle();
    void rebuild();
    void updateConnection(enum nf_conntrack_msg_type type, Connection& connection);
    bool isIgnoredHost(const string& host) const;

    static int nfct_callback_attach(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);
    static int nfct_callback_rebuild(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data);
    static int nfct_callback_dummy(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data) { return NFCT_CB_STOP; }

    nfct_handle* attach_handle;
    nfct_handle* rebuild_handle;
    bool is_rebuilding;
    bool log_events = false;
    string log_events_format = "netfilter";
    bool debugging = false;
    ConnectionList connections;
    list<string> ignored_hosts;
};

} // namespace conntrackex
