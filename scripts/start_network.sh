
#!/bin/bash

#Generate the server.pem and server_key.pem
openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

# Start the setup_node
echo "Starting setup_node..."
nohup ./node "setup_node" "127.0.0.1" "4455" > setup_node.log 2>&1 &
sleep 2

# Start cofhe_node on port 4456
echo "Starting cofhe_node on port 4456..."
nohup ./node "cofhe_node" "127.0.0.1" "4456" "127.0.0.1" "4455" > cofhe_node_4456.log 2>&1 &
sleep 2

# Start cofhe_node on port 4457
echo "Starting cofhe_node on port 4457..."
nohup ./node "cofhe_node" "127.0.0.1" "4457" "127.0.0.1" "4455" > cofhe_node_4457.log 2>&1 &
sleep 2

# Start cofhe_node on port 4458
echo "Starting cofhe_node on port 4458..."
nohup ./node "cofhe_node" "127.0.0.1" "4458" "127.0.0.1" "4455" > cofhe_node_4458.log 2>&1 &
sleep 2

# Start compute_node on port 4459
echo "Starting compute_node on port 4459..."
nohup ./node "compute_node" "127.0.0.1" "4459" "127.0.0.1" "4455" > compute_node.log 2>&1 &
sleep 2

# echo "Waiting for the nodes to start..."
# sleep 10
# echo "Starting client_node to tes"
# ./node "client_node" "127.0.0.1" "4456" "127.0.0.1" "4455"