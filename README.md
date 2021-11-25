# SOC-SIEM
## Prerequisites
Some extra packages are needed for the installation, such us ```curl``` or ```unzip```, that will be used in further steps:
```sh
apt-get install apt-transport-https zip unzip lsb-release curl gnupg
```
## Installing Elasticsearch
Elasticsearch is a highly scalable full-text search and analytics engine.
### Adding the Elastic Stack repository
- Install the GPG key:
```sh
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
```
- Add the repository:
```sh
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
```
- Update the package information:
```sh
apt-get update
```
###  Elasticsearch installation and configuration
- Install the Elasticsearch package:
```sh
apt-get install elasticsearch=7.14.2
```
- Download the configuration file ```/etc/elasticsearch/elasticsearch.yml``` as follows:
```sh
curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/resources/4.2/elastic-stack/elasticsearch/7.x/elasticsearch_all_in_one.yml
```
### Certificates creation and deployment
- Download the configuration file for creating the certificates:
```sh
curl -so /usr/share/elasticsearch/instances.yml https://packages.wazuh.com/resources/4.2/elastic-stack/instances_aio.yml
```
In the following steps, a file that contains a folder named after the instance defined here will be created. This folder will contain the certificates and the keys necessary to communicate with the Elasticsearch node using SSL.
- The certificates can be created using the elasticsearch-certutil tool:
```sh
/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip
```
- Extract the generated ```/usr/share/elasticsearch/certs.zip``` file from the previous step.
```sh
unzip ~/certs.zip -d ~/certs
```
- The next step is to create the directory ```/etc/elasticsearch/certs```, and then copy the CA file, the certificate and the key there:
```sh
mkdir /etc/elasticsearch/certs/ca -p
cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/
chown -R elasticsearch: /etc/elasticsearch/certs
chmod -R 500 /etc/elasticsearch/certs
chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.*
rm -rf ~/certs/ ~/certs.zip
```
- Enable and start the Elasticsearch service:
```sh
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
```
- Generate credentials for all the Elastic Stack pre-built roles and users:
```sh
/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
```
The command above will prompt an output. Save the password of the ```elastic``` user for further steps:
To check that the installation was made successfully, run the following command replacing ```<elastic_password>``` by the password generated on the previous step for ```elastic``` user:
```sh
curl -XGET https://localhost:9200 -u elastic:<elastic_password> -k
```
This command should have an output like this:
```json
 {
   "name" : "elasticsearch",
   "cluster_name" : "elasticsearch",
   "cluster_uuid" : "upF9h1afQN2TfHtt0h3Kuw",
   "version" : {
     "number" : "7.14.2",
     "build_flavor" : "default",
     "build_type" : "rpm",
     "build_hash" : "6bc13727ce758c0e943c3c21653b3da82f627f75",
     "build_date" : "2021-09-15T10:18:09.722761972Z",
     "build_snapshot" : false,
     "lucene_version" : "8.9.0",
     "minimum_wire_compatibility_version" : "6.8.0",
     "minimum_index_compatibility_version" : "6.0.0-beta1"
   },
   "tagline" : "You Know, for Search"
 }
```
## Installing Wazuh server
- Install the GPG key:
```sh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
```
- Add the repository:
```sh
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```
- Update the package information:
```sh
apt-get update
```
### Installing the Wazuh manager
- Install the Wazuh manager package:
```sh
apt-get install wazuh-manager
```
- Enable and start the Wazuh manager service:
```sh
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```
- Run the following command to check if the Wazuh manager is active:
```sh
systemctl status wazuh-manager
```
## Installing Filebeat
Filebeat is the tool on the Wazuh server that securely forwards alerts and archived events to Elasticsearch.
- Install the Filebeat package:
```sh
apt-get install filebeat=7.14.2
```
- Download the pre-configured Filebeat config file used to forward Wazuh alerts to Elasticsearch:
```sh
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/resources/4.2/elastic-stack/filebeat/7.x/filebeat_all_in_one.yml
```
- Download the alerts template for Elasticsearch:
```sh
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
```
- Download the Wazuh module for Filebeat:
```sh
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
```
- Edit the file ```/etc/filebeat/filebeat.yml```:
```sh
output.elasticsearch.password: <elasticsearch_password>
```
Replace ```elasticsearch_password``` with the previously generated password for ```elastic``` user.
- Copy the certificates into ```/etc/filebeat/certs/```
```sh
cp -r /etc/elasticsearch/certs/ca/ /etc/filebeat/certs/
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/filebeat/certs/filebeat.crt
cp /etc/elasticsearch/certs/elasticsearch.key /etc/filebeat/certs/filebeat.key
```
- Enable and start the Filebeat service:
```sh
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
```
- To ensure that Filebeat has been successfully installed, run the following command:
```sh
filebeat test output
```
## Kibana installation and configuration
Kibana is a flexible and intuitive web interface for mining and visualizing the events and archives stored in Elasticsearch.
- Install the Kibana package:
```sh
apt-get install kibana=7.14.2
```
- Copy the Elasticsearch certificates into the Kibana configuration folder:
```sh
mkdir /etc/kibana/certs/ca -p
cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/
cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt
chown -R kibana:kibana /etc/kibana/
chmod -R 500 /etc/kibana/certs
chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*
```
- Download the Kibana configuration file:
```sh
curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/resources/4.2/elastic-stack/kibana/7.x/kibana_all_in_one.yml
```
- Edit the ```/etc/kibana/kibana.yml``` file:
```sh
elasticsearch.password: <elasticsearch_password>
```
- Create the ```/usr/share/kibana/data``` directory:
```sh
mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana
```
- Install the Wazuh Kibana plugin. The installation of the plugin must be done from the Kibana home directory as follows:
```sh
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.2.5_7.14.2-1.zip
```
- Link Kibana’s socket to privileged port 443:
```sh
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
```
- Enable and start the Kibana service:
```sh
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana
```
- Access the web interface using the password generated during the Elasticsearch installation process:
```sh
URL: https://<wazuh_server_ip>
user: elastic
password: <PASSWORD_elastic>
```
## Disabling repositories
```sh
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/elastic-7.x.list
apt-get update
```
