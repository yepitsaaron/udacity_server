https://github.com/yepitsaaron/udacity_server.git

# get environment configured
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install apache2
sudo apt-get install libapache2-mod-wsgi

sudo a2enmod wsgi
sudo apt-get install python-pip
sudo pip install virtualenv
sudo apt-get install postgresql
sudo apt-get install git
sudo virtualenv venv

# create grader account
sudo adduser grader
password: grader
sudo cp /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/grader
sudo nano /etc/sudoers.d/grader
-- change old user to grader

# setup grader private key
locally:
	sudo mkdir /users/grader
	sudo mkdir /users/grader/.ssh
	sudo ssh-keygen
	enter: /users/grader/.ssh/lightsail
	password: grader
	note: the private key needs to be sent to grader
	cat /users/grader/.ssh/lightsail.pub
	copy RSA key to clipboard
on AWS:
	su grader
	cd ~
	mkdir .ssh
	touch .ssh/authorized_keys
	sudo nano .ssh/authorized_keys
	paste key & save / exit
	chmod 700 .ssh
	chmod 644 .ssh/authorized_keys

# setup UFW
sudo nano /etc/ssh/sshd_config
## change ssh to port 2200 & save/exit
## note: also need to add this to the amazon instance under networking
sudo ufw allow 2200/tcp
sudo ufw allow 80/tcp
sudo ufw allow 123/udp
sudo ufw enable
sudo service ssh restart

# setup postgres user
sudo su postgres
psql
create database catalog;
create user catalog;
\password catalog
change to catalog \ catalog
\q
exit


# activate python env
source venv/bin/activate
sudo pip install Flask
sudo pip install psycopg2
sudo pip install sqlalchemy
pip install sqlalchemy
sudo pip install oauth2client
sudo pip install requests

cd /etc/www
sudo git clone https://github.com/yepitsaaron/udacity_server.git ./catalog
cd catalog/catalog
python database_setup.py
python dummy_data.py
sudo python project.py -- just test it works & serves on port 5000
deactivate

# make the project the default
sudo nano /etc/apache2/sites-available/000-default.conf
add: WSGIScriptAlias / /var/www/catalog/catalog.wsgi

sudo apache2ctl restart