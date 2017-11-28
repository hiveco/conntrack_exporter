#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <signal.h>

#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include "connection_table.h"

using namespace std;
using namespace prometheus;
using namespace conntrackex;


// Allow Ctrl+C to break the main loop:
static volatile int keep_running = 1;
void sigint_handler(int)
{
    cout << "Stopping conntrack_exporter" << endl;
    keep_running = 0;
}

int main(int argc, char** argv)
{
    signal(SIGINT, sigint_handler);

    const string listen_port = "9100";

    cout << "conntrack_exporter v0.1" << endl;

    // Create an HTTP server on the listen port:
    Exposer exposer{"0.0.0.0:" + listen_port};
    ConnectionTable table;

    cout << "Serving metrics at http://localhost:" << listen_port << "/metrics ..." << endl;

    while (keep_running) {

        // Build up a registry and metric families:
        auto registry = make_shared<Registry>();
        auto& opening_connections_family = BuildGauge()
            .Name("conntrack_opening_connections_total")
            .Help("How many connections to the remote host are currently opening?")
            .Register(*registry);
        auto& open_connections_family = BuildGauge()
            .Name("conntrack_open_connections_total")
            .Help("How many open connections are there to the remote host?")
            .Register(*registry);
        auto& closing_connections_family = BuildGauge()
            .Name("conntrack_closing_connections_total")
            .Help("How many connections to the remote host are currently closing?")
            .Register(*registry);
        auto& closed_connections_family = BuildGauge()
            .Name("conntrack_closed_connections_total")
            .Help("How many connections to the remote host have recently closed?")
            .Register(*registry);

        // Add guages for the individual connections:
        table.rebuild();
        auto connections = table.getConnections();
        for (auto connection : connections)
        {
            Gauge* pGuage;
            switch (connection.getState())
            {
                case ConnectionState::OPENING:
                    pGuage = &opening_connections_family.Add({{"host", connection.getRemoteHost()}});
                    break;
                case ConnectionState::OPEN:
                    pGuage = &open_connections_family.Add({{"host", connection.getRemoteHost()}});
                    break;
                case ConnectionState::CLOSING:
                    pGuage = &closing_connections_family.Add({{"host", connection.getRemoteHost()}});
                    break;
                case ConnectionState::CLOSED:
                    pGuage = &closed_connections_family.Add({{"host", connection.getRemoteHost()}});
                    break;
                default:
                    continue;
            }
            pGuage->Increment();
        }

        exposer.RegisterCollectable(registry);

        this_thread::sleep_for(chrono::seconds(1));
    }

    exit(0);
}
