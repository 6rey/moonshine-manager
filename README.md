
Client side
    How run on Windows PC
- git clone git@github.com:6rey/moonshine-manager.git
cmd form app folder
- cd client
    Install python dependencies
- pip install customtkinter requests PyJWT urllib3 zeroconf

    Run Client app
- python admin_sunshine.py

Need enter admin \ password (needed entered in server side in Docker)

Server side
    How run linix server
    Docker & Docker Compose must be installed
- git clone git@github.com:6rey/moonshine-manager.git
- cd server
- run docker-compose up
check all docker containers start and running
Initilize server 
Solve python dependencies
- docker exec -it vdi_api /bin/bash
- pip uninstall bcrypt passlib python-bcrypt -y
- pip install passlib==1.7.4 bcrypt==4.1.2

- start ./run_init.sh
All setting defaul
postgres user - myuser
postgres user - mypass
host - vdi_db
user admin - admin
password admin - enter your password
save - o
 Restart Docker containers 
 - docker-compose stop
 - docker-compose up
 
 Now you check and try login to client app

 Client app JS + Electron

 Check Moonlight and Sunshine
 copy Moonlight to C:\mootlight
 start on Windows PC Sunshine server and chanhe user\password

 Now on client side app you
 - create user
 - find PC Sunshine server and add to internal DB app
 - try connect Moonlight to Sunshine