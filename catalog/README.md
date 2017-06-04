This is a basic item catalog / content management system using the Flask
framework in Python.

Authentication is provided via OAuth and all data is stored within a
Postgres db.

To run the application (assuming you have the standard Udacity Vagrant setup):

* vagrant up --> start the VM
* vagrant ssh --> ssh to VM
* cd to project directory
* python database_setup.py --> create initial database
* python dummy_data.py --> seed database w/ dummy data
* python project.py --> run application
* open browser, navigate to http://localhost:5000 (or http://0.0.0.0:5000 if
 you haven't forwarded the vagrant ports)
