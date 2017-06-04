# get base environment upgraded
sudo apt-get update
sudo apt-get upgrade

# install other base software
sudo apt-get install apache2
sudo apt-get install libapache2-mod-wsgi
sudo a2enmod wsgi
sudo apt-get install python-pip

# install virutal environment
sudo pip install virtualenv
sudo virtualenv venv
source venv/bin/activate
sudo pip install Flask
sudo pip install psycopg2

# setup database
sudo python database_setup.py
sudo python dummy_data.py

sudo python project.py