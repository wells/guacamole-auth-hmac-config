sudo su
apt-get update
apt-get install -y tomcat7 
apt-get install -y build-essential
apt-get install -y automake
apt-get install -y libtool
apt-get install -y shtool
apt-get install -y checkinstall
apt-get install -y git
apt-get install -y libcairo2-dev
apt-get install -y libjpeg-dev
apt-get install -y libpng12-dev
apt-get install -y libossp-uuid-dev
apt-get install -y libfreerdp-dev
apt-get install -y libpango1.0-dev
apt-get install -y libssh2-1-dev
apt-get install -y libtelnet-dev
apt-get install -y libvncserver-dev
apt-get install -y libpulse-dev
apt-get install -y libssl-dev
apt-get install -y libvorbis-dev
apt-get install -y libwebp-dev
cd /usr/share/tomcat7
rm -f webapps
ln -s /var/lib/tomcat7/conf conf
ln -s /var/lib/tomcat7/webapps webapps
chmod 777 /usr/share/tomcat7/webapps
cp /vagrant/target/guacamole-0.9.9.war /usr/share/tomcat7/webapps/guacamole.war
cp /vagrant/target/guacamole-server-0.9.9.tar.gz /tmp
cd /tmp
tar xvzf guacamole-server-0.9.9.tar.gz
cd guacamole-server-0.9.9
./configure --with-init-dir=/etc/init.d
make
make install
ldconfig
update-rc.d guacd defaults
if [[ ! -d /etc/guacamole ]]
then
    mkdir /etc/guacamole;
    touch /etc/guacamole/guacamole.properties
    touch /etc/guacamole/hmac-config.xml
    mkdir /etc/guacamole/extensions
fi
cp /vagrant/target/guacamole-auth-hmac-config-0.9.9.jar /etc/guacamole/extensions/
ln -s /etc/guacamole /usr/share/tomcat7/.guacamole
service guacd restart
service tomcat7 restart
exit