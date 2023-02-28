#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>





/*variables de control*/

#define T 1
#define P 2
#define Q 3
#define U 2
#define N 6
#define O 2
#define R 2
#define S 3




/*estructuras*/

struct ConfigPackage{
    unsigned char pdu_type;
    char id[7];
    char mac_adress[13];
    char num_ale[7];
    char data[50];
};
struct Package{
    unsigned char pdu_type;
    char id[7];
    char mac_adress[13];
    char num_ale[7];
    char data[50];

};
struct Client{
    char id[7];
    char mac_a[13];
};

struct Server{
    char id[20];
    char *adress;
    char mac_a[13];
    char num_ale[7];
};

struct Sockets_UDP{
    int udp_socket;
    int udp_port;
    struct timeval udp_timeout;
    struct sockaddr_in udp_addr_server;

};
struct Sockets_TCP{
    int tcp_socket;
    int tcp_port;
    struct timeval tcp_timeout;
    struct sockaddr_in tcp_addr_server;
};


/*Global variables*/

bool debug_mode = false;
char *network_dev_config_file_name = NULL;
struct Client client_data;
int unsuccefull_client_signup;
struct Server server_data;
struct Sockets_UDP sockets_udp;
struct Sockets_TCP sockets_tcp;
char *client_state = NULL;
pthread_t thread_comm;


/*function declarations*/
void end(int signal);
void config_from_file(int argc, const char *argv[]);
void print_message(char *message);
void save_config(FILE *file);
void setup_udp_socket();
void service();
void registration();
void change_client_state(char *newstate);
void register_to_server();
struct Package build_register_data_package();
unsigned char get_packet_type(char *string);
char *get_packet_string(unsigned char type);
int get_waiting_time_after_sent(int reg_reqs_sent);
void send_package_udp_to_server(struct Package package);
void prepare_receive_package_udp(fd_set rfds, int timeout);
struct Package receive_package_via_udp(fd_set rfds);
void save_regiter_ack_data_respo(struct Package recieve_data);
void *command_input();
void *mantain_comunication();

/*main*/
int main(int argc, const char *argv[]){
    unsuccefull_client_signup = 0;
    strcpy(server_data.num_ale, "000000");

    signal(SIGINT, end);
     /*read and save the configuration from the config file*/
    config_from_file(argc,argv);
    setup_udp_socket();
    service();
}



/*fuctions*/
void end(int signal){
    if(signal == SIGINT){
        write(2,"\nExiting client...\n",20);


        close(sockets_tcp.tcp_socket);
        close(sockets_udp.udp_socket);
        free(client_state);
        free(server_data.adress);
        exit(0);
    }
}




void config_from_file(int argc, const char *argv[]){
    FILE *config_file = NULL;
    for(int i=0; i<argc; i++){
        if(strcmp(argv[i], "-c")==0 && argc > (i+1)){
            if(access(argv[i+1],F_OK)!=-1){
                config_file = fopen(argv[i+1], "r");
            }else{
                char message[200];
                sprintf(message, "ERROR ->Can't open file named '%s'. WIll open the default client.cfg \n", argv[i+1]);
                print_message(message);
            }
        }else if(strcmp(argv[i], "-d")==0){
            debug_mode = true;
            print_message("INFO ->Debug mode enabled\n");

        }else if(strcmp(argv[i],"-f")==0 && argc >(i+1)){
            network_dev_config_file_name = malloc(sizeof(argv[i+1]));
            strcpy(network_dev_config_file_name,argv[i+1]);
        }
    }
    if(debug_mode) print_message("DEBUG-> Read command line input\n");
    if(config_file==NULL){
        if(access("client.cfg",F_OK)!=-1){
            config_file = fopen("client.cfg", "r");
        }else{
            print_message("ERROR ->Can't find default file named client.cfg in this directory\n");
            exit(1);
        }
    }
    if(network_dev_config_file_name == NULL) { // save default
        network_dev_config_file_name = malloc(sizeof("boot.cfg"));
        strcpy(network_dev_config_file_name, "boot.cfg");
    }
    save_config(config_file);
    if (debug_mode) { print_message("DEBUG -> Read data from configuration files\n"); }
}

void print_message(char *message){
    time_t now;
    struct tm *now_tw;
    char forwarted_time[100];


    now = time(NULL);
    now_tw = localtime(&now);
    strftime(forwarted_time, 100, "%H:%M:%S", now_tw);
    printf("%s - %s", forwarted_time, message);
    fflush(stdout);
}


void save_config(FILE *file){
    char line[70];
    char *token;
    char delim[] =" \n";

    
    /*read line by line*/
    while(fgets(line, 70, file)){
        token = strtok(line,delim);

        if(strcmp(token,"Id")==0){
            token = strtok(NULL,delim);
            strcpy(client_data.id,token);
        }else if(strcmp(token,"MAC")==0){
            token= strtok(NULL,delim);
            strcpy(client_data.mac_a,token);
        }else if(strcmp(token,"NMS-Id") == 0){
            token= strtok(NULL,delim);
            server_data.adress = malloc(strlen(token) + 1);
            strcpy(server_data.adress,token);
        }else if(strcmp(token,"NMS-UDP-port") == 0){
            sockets_udp.udp_port = atoi(strtok(NULL,delim));
        }
    }
}


void setup_udp_socket(){
    struct hostent *ent;
    struct sockaddr_in addr_cli;


    ent = gethostbyname(server_data.adress);

    if (!ent) {
        print_message("ERROR -> Can't find server on trying to setup UDP socket\n");
        exit(1);
    }

    sockets_udp.udp_socket = socket(AF_INET,SOCK_DGRAM,0);
    if(sockets_udp.udp_socket < 0){
        print_message("ERROR -> Could not create UDP socket\n");
        exit(1);
    }


    /*colocamos en la estructura las direcciones con las que se vinculara el cliente */
    memset(&addr_cli, 0, sizeof(struct sockaddr_in));
    addr_cli.sin_family = AF_INET;
    addr_cli.sin_addr.s_addr =htonl(INADDR_ANY);
    addr_cli.sin_port = htons(0);

    /*vinculamos*/
    if(bind(sockets_udp.udp_socket, (struct sockaddr*) &addr_cli, sizeof(struct sockaddr_in))<0){
        print_message("ERROR ->Could not bind UDP socket\n");
        exit(1);
    }

    /*colocamos en la estructura del servidor las direcciones donde enviaremos los fichero*/
    memset(&sockets_udp.udp_addr_server, 0, sizeof(struct sockaddr_in));
    sockets_udp.udp_addr_server.sin_family = AF_INET;
    sockets_udp.udp_addr_server.sin_addr.s_addr = (((struct in_addr *) ent->h_addr_list[0])->s_addr);
    sockets_udp.udp_addr_server.sin_port = htons(sockets_udp.udp_port);
}

void service(){
    //the register to server
    registration();
    pthread_create(&thread_comm,NULL,command_input,NULL);
    mantain_comunication();
}
void registration(){
    change_client_state("DISCONNECTED");
    register_to_server();
}
void change_client_state(char *newstate){
    client_state = malloc(sizeof(newstate));
    strcpy(client_state, newstate);
    char message[50];
    sprintf(message, "INFO -> Client_state changed to: %s\n", client_state);
    print_message(message);
}
void register_to_server(){
    while (unsuccefull_client_signup < O){
        if(debug_mode){
            char message[75];
            sprintf(message, "DEBUG -> Starting new register process. Current tries: %d / %d \n", unsuccefull_client_signup+ 1, O);
            print_message(message);
        }

        for(int request = 0; request < N; request++){
            struct Package register_data_required;
            register_data_required = build_register_data_package();
            send_package_udp_to_server(register_data_required);
            change_client_state("WAIT_REG_RESPONSE");
            struct Package received_data_server;
            fd_set rfds;
            prepare_receive_package_udp(rfds,get_waiting_time_after_sent(request));
            received_data_server = receive_package_via_udp(rfds);
            if(received_data_server.pdu_type == get_packet_type("REGISTER_REJ")){
                change_client_state("DISCONNECTED");
            }else if(received_data_server.pdu_type == get_packet_type("REGISTER_NACK")){
                break;
            }else if(received_data_server.pdu_type == get_packet_type("REGISTER_ACK")){
                change_client_state("REGISTERED");
                save_regiter_ack_data_respo(received_data_server);
                if(debug_mode){
                    char message[150];
                    sprintf(message,
                            "Succefull register fase on server: %s (id: %s, mac: %s, num_ale: %s, tcp_port: %d)\n",
                            server_data.adress,server_data.id,server_data.mac_a,
                            server_data.num_ale, sockets_tcp.tcp_port);
                    print_message(message);

                }
                return; 
            }else if(debug_mode){
                print_message("DEBUG -> No answer received for REGISTER_REQ\n\n");
                print_message("DEBUG -> Trying to reach server again...\n");
            }
            sleep(sockets_udp.udp_timeout.tv_sec);
            usleep(sockets_udp.udp_timeout.tv_usec);
             
        }
        sleep(U);
        unsuccefull_client_signup++;
    }
    print_message("ERROR -> Could not contact server. Maximum tries to contact server have been reached\n");
    exit(1); 
 
}
struct Package build_register_data_package(){
    struct Package register_req;

    register_req.pdu_type = get_packet_type("REGISTER_REQ");
    strcpy(register_req.id, client_data.id);
    strcpy(register_req.mac_adress, client_data.mac_a);
    strcpy(register_req.num_ale, server_data.num_ale);
    strcpy(register_req.data, "");
    return register_req;
}


unsigned char get_packet_type(char *string){
    unsigned char packet_type;
    if(strcmp(string,"REGISTER_REQ")==0){
        packet_type = (unsigned char) 0x00;
    }else if(strcmp(string,"REGISTER_ACK")==0){
        packet_type = (unsigned char) 0x02;
    }else if(strcmp(string,"REGISTER_NACK")==0){
        packet_type = (unsigned char) 0x04;
    }else if(strcmp(string,"REGISTER_REJ")==0){
        packet_type = (unsigned char) 0x06;
    }else if(strcmp(string,"ERROR")==0){
        packet_type = (unsigned char) 0x0F;
    }else if(strcmp(string,"DISCONNECTED")==0){
        packet_type = (unsigned char) 0xA0;
    }else if(strcmp(string,"WAIT_REG_RESPONSE")==0){
        packet_type = (unsigned char) 0xA2;
    }else if(strcmp(string,"WAIT_DB_CHECK")==0){
        packet_type = (unsigned char) 0xA4;
    }else if(strcmp(string,"REGISTERED")==0){
        packet_type = (unsigned char) 0xA6;
    }else if(strcmp(string,"SEND_ALIVE")==0){
        packet_type = (unsigned char) 0xA8;
    }else if(strcmp(string,"ALIVE_INF")==0){
        packet_type = (unsigned char) 0x10;
    }else if(strcmp(string,"ALIVE_ACK")==0){
        packet_type = (unsigned char) 0x12;
    }else if(strcmp(string,"ALIVE_NACK")==0){
        packet_type = (unsigned char) 0x14;
    }else if(strcmp(string,"ALIVE_REJ")==0){
        packet_type = (unsigned char) 0x16;
    }else if(strcmp(string,"SEND_FILE")==0){
        packet_type = (unsigned char) 0x20;
    }else if(strcmp(string,"SEND_DATA")==0){
        packet_type = (unsigned char) 0x22;
    }else if(strcmp(string,"SEND_ACK")==0){
        packet_type = (unsigned char) 0x24;
    }else if(strcmp(string,"SEND_NACK")==0){
        packet_type = (unsigned char) 0x26;
    }else if(strcmp(string,"SEND_REJ")==0){
        packet_type = (unsigned char) 0x28;
    }else if(strcmp(string,"SEND_END")==0){
        packet_type = (unsigned char) 0x2A;
    }else if(strcmp(string, "GET_FILE")==0){
        packet_type = (unsigned char) 0x30;
    }else if(strcmp(string, "GET_DATA")==0){
        packet_type = (unsigned char) 0x32;
    }else if(strcmp(string, "GET_ACK")==0){
        packet_type = (unsigned char) 0x34;
    }else if(strcmp(string, "GET_NACK")==0){
        packet_type = (unsigned char) 0x36;
    }else if(strcmp(string, "GET_REJ")==0){
        packet_type = (unsigned char) 0x38;
    }else if(strcmp(string, "GET_END")==0){
        packet_type = (unsigned char) 0x3A;
    }
    return packet_type;                                                  
}


char *get_packet_string(unsigned char type){
    char *packet;

    if (type == (unsigned char) 0x00){
        packet = "REGISTER_REQ";
    }else if (type == (unsigned char) 0x02){
        packet = "REGISTER_ACK";
    }else if (type == (unsigned char) 0x04){
        packet = "REGISTER_NACK";
    }else if (type == (unsigned char) 0x06){
        packet = "REGISTER_REJ";
    }else if (type == (unsigned char) 0x0F){
        packet = "ERROR";
    }else if (type == (unsigned char) 0xA0){
        packet = "DISCONNECTED";
    }else if (type == (unsigned char) 0xA2){
        packet = "WAIT_REG_RESPONSE";
    }else if (type == (unsigned char) 0xA4){
        packet = "WAIT_DB_CHECK";
    }else if (type == (unsigned char) 0xA6){
        packet = "REGISTERED";
    }else if (type == (unsigned char) 0xA8){
        packet = "SEND_ALIVE";
    }else if (type == (unsigned char) 0x10){
        packet = "ALIVE_INF";
    }else if (type == (unsigned char) 0x12){
        packet = "ALIVE_ACK";
    }else if (type == (unsigned char) 0x14){
        packet = "ALIVE_NACK";
    }else if (type == (unsigned char) 0x16){
        packet = "ALIVE_REJ";
    }else if (type == (unsigned char) 0x20){
        packet = "SEND_FILE";
    }else if (type == (unsigned char) 0x22){
        packet = "SEND_DATA";
    }else if (type == (unsigned char) 0x24){
        packet = "SEND_ACK";
    }else if (type == (unsigned char) 0x26){
        packet = "SEND_NACK";
    }else if (type == (unsigned char) 0x28){
        packet = "SEND_REJ";
    }else if (type == (unsigned char) 0x2A){
        packet = "SEND_END";
    }else if (type == (unsigned char) 0x30){
        packet = "GET_FILE";
    }else if (type == (unsigned char) 0x32){
        packet = "GET_DATA";
    }else if (type == (unsigned char) 0x34){
        packet = "GET_ACK";
    }else if (type == (unsigned char) 0x36){
        packet = "GET_NACK";
    }else if (type == (unsigned char) 0x38){
        packet = "GET_REJ";
    }else if (type == (unsigned char) 0x3A){
        packet = "GET_END";
    }
    return packet;
}
int get_waiting_time_after_sent(int reg_reqs_sent) { /* note: reg_reqs_sent starts at 0 */
    if (reg_reqs_sent >= P - 1) {
        int times = 2 + (reg_reqs_sent + 1 - P);
        if (times > Q) {
            times = Q;
        }
        return times * T;
    }
    return T;
}
void send_package_udp_to_server(struct Package package){
    int send = sendto(sockets_udp.udp_socket, &package, sizeof(package), 0, (struct sockaddr *)&sockets_udp.udp_addr_server, sizeof(sockets_udp.udp_addr_server));

    char msg[200];
    if(send < 0){
        sprintf(msg, "ERROR -> Package %s not sent via UDP \n", get_packet_string(package.pdu_type));
        print_message(msg);
    }else if(debug_mode){
        sprintf(msg,
                "DEBUG -> Sent %s;\n"
                "\t\t\t Bytes:%lu,\n"
                "\t\t\t id:%s,\n"
                "\t\t\t MAC: %s,\n"
                "\t\t\t num ale:%s\n"
                "\t\t\t data:%s\n",
                get_packet_string(package.pdu_type), sizeof(package),
                package.id, package.mac_adress, package.num_ale,   
                package.data);
        print_message(msg);
    }
}
void prepare_receive_package_udp(fd_set rfds, int timeout){
    FD_ZERO(&rfds);
    FD_SET(sockets_udp.udp_socket, &rfds);
    sockets_udp.udp_timeout.tv_sec = timeout;
    sockets_udp.udp_timeout.tv_usec = 0;

}
struct Package receive_package_via_udp(fd_set rfds){
    char *buf = malloc(sizeof(struct Package));
    struct Package *recieve_package = malloc(sizeof(struct Package));
    
    int rec;
    rec = recvfrom(sockets_udp.udp_socket, buf, sizeof(struct Package), 0,(struct sockaddr *) 0,(socklen_t *) 0);
    if(rec<0){
        print_message("ERROR -> Could not recive from UDP socket \n");
    }else{
        recieve_package = (struct Package *) buf;
        if(debug_mode){
            char mess[200];
            sprintf(mess,
                    "DEBUG -> Sent %s;\n"
                    "\t\t\t Bytes:%lu,\n"
                    "\t\t\t id:%s,\n"
                    "\t\t\t MAC: %s,\n"
                    "\t\t\t num ale:%s\n"
                    "\t\t\t data:%s\n",
                    get_packet_string((unsigned char)(*recieve_package).pdu_type),
                    sizeof(*recieve_package), (*recieve_package).id, 
                    (*recieve_package).mac_adress, (*recieve_package).num_ale,
                    (*recieve_package).data);
            print_message(mess);
        }
    }       
        
    return *recieve_package;

}
void save_regiter_ack_data_respo(struct Package recieve_data){
    strcpy(server_data.num_ale,recieve_data.num_ale);
    strcpy(server_data.mac_a,recieve_data.mac_adress);
    strcpy(server_data.id,recieve_data.id);
    sockets_tcp.tcp_port=atoi(recieve_data.data);
}

void *command_input(){
    while(1){
        int max_char_can_read = 50;
        char buffer[max_char_can_read];
        if(fgets(buffer, max_char_can_read, stdin) != NULL){
            buffer[strcspn(buffer, "\n")] = '0';
        }
        char *c_buff = malloc(max_char_can_read);
        strcpy(c_buff,buffer);

        if(strcmp(c_buff,"send-cfg")){

        }else if(strcmp(c_buff,"get-cfg")){

        }else if(strcmp(c_buff,"quit")){

        }else{
            char message[150];
            sprintf(message, "ERROR -> %s is not an accepted command\n", c_buff);
            print_message(message);
            print_message("INFO  -> Accepted commands are: \n");
            printf("\t\t    send-cfg -> sends conf file to server via TCP\n");
            printf("\t\t    get-cfg -> receive conf from server via TCP and save the conf on file");
            printf("\t\t    quit -> finishes client\n");
        }
    }
}


void *mantain_comunication(){
    return NULL;
}


