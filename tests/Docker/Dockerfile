FROM rishabhpoddar/supertokens_core_testing

RUN apt update && apt install software-properties-common -y

RUN apt install python3-pip -y

RUN echo 'alias python=python3' >> ~/.bashrc

RUN echo 'alias pip=pip3' >> ~/.bashrc

RUN pip3 install --upgrade pip