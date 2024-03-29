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
#define W 3



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
pthread_t thread_comm = (pthread_t) NULL;


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
struct Package receive_package_via_udp(int timeout);
void save_regiter_ack_data_respo(struct Package recieve_data);
void *command_input();
void *mantain_comunication();
struct Package build_alive_inf_tosend_package();
bool check_received_package_ack_is_valid_udp(struct Package package);
void execute_send_cfg();
void setup_tcp_socket();
struct ConfigPackage build_Sent_file();
void send_package_tcp_to_server(struct ConfigPackage package);
struct ConfigPackage receive_package_via_tcp(int timeout);
bool check_received_package_ack_is_valid_tcp(struct ConfigPackage received, unsigned char expected_type);
struct ConfigPackage build_send_end();
struct ConfigPackage build_get_confg(FILE *config_file);
void execute_get_cfg();

/*main*/
int main(int argc, const char *argv[]){
    unsuccefull_client_signup = 0;
    strcpy(server_data.num_ale, "000000");

    signal(SIGINT, end);
     /*read and save the configuration from the config file*/
    config_from_file(argc,argv);
    setup_udp_socket();
    service();

    return 0;
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
            received_data_server = receive_package_via_udp(get_waiting_time_after_sent(request));
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
struct Package receive_package_via_udp(int timeout){
    fd_set rfds;

    char *buf = malloc(sizeof(struct Package));
    struct Package *recieve_package = malloc(sizeof(struct Package));

    FD_ZERO(&rfds);
    FD_SET(sockets_udp.udp_socket, &rfds);
    sockets_udp.udp_timeout.tv_sec = timeout;
    sockets_udp.udp_timeout.tv_usec = 0;

    if(select(sockets_udp.udp_socket + 1, &rfds, NULL, NULL, &sockets_udp.udp_timeout)){
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
    }
          
        
    return *recieve_package;

}
void save_regiter_ack_data_respo(struct Package recieve_data){
    strcpy(server_data.num_ale,recieve_data.num_ale);
    strcpy(server_data.mac_a,recieve_data.mac_adress);
    strcpy(server_data.id,recieve_data.id);
    sockets_tcp.tcp_port=atoi(recieve_data.data);
}

char *read_from_stdin(int max_char_can_read){
    char buffer[max_char_can_read];
        if(fgets(buffer, max_char_can_read, stdin) != NULL){
            buffer[strcspn(buffer, "\n")] = '\0';
        }
        char *c_buff = malloc(max_char_can_read);
        strcpy(c_buff,buffer);
        return c_buff;
}

void *command_input(){
    while(1){
        int max_char_can_read = 50;
        
        char *c_buff = read_from_stdin(max_char_can_read);

        if(strcmp(c_buff,"send-cfg")){
            execute_send_cfg();
        }else if(strcmp(c_buff,"get-cfg")){
            execute_get_cfg();
        }else if(strcmp(c_buff,"quit")){
            end(SIGINT);
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
    int failed_recived_ack=0;
    while(1){
        struct Package alive_if_to_send= build_alive_inf_tosend_package();
        send_package_udp_to_server(alive_if_to_send);
        struct Package received_package_via_udp = receive_package_via_udp(get_waiting_time_after_sent(R));
        sleep(sockets_udp.udp_timeout.tv_sec);
        usleep(sockets_udp.udp_timeout.tv_usec);



        if(received_package_via_udp.pdu_type == get_packet_type("ALIVE_ACK") && 
                check_received_package_ack_is_valid_udp(received_package_via_udp)){
                if (strcmp(client_state, "ALIVE") != 0) { change_client_state("ALIVE"); }
                failed_recived_ack = 0;
        }else if(received_package_via_udp.pdu_type == get_packet_type("ALIVE_ACK") && 
                 !check_received_package_ack_is_valid_udp(received_package_via_udp)){
                failed_recived_ack++;
                if(debug_mode){
                    char msg[200];
                    sprintf(msg,
                            "DEBUG -> Received incorrect ALIVE_ACK package. Incorrect pdu-fields"
                            "received.\n"
                            "Correct pdu-fields :(id: %s ,mac: %s, num_ale: %s)\n\n",
                             server_data.id, server_data.mac_a, server_data.num_ale);
                    print_message(msg);         
                }
        }else if(received_package_via_udp.pdu_type == get_packet_type("ALIVE_REJ") && strcmp(client_state, "ALIVE")==0){
            print_message("INFO  -> Potential impersonation Got ALIVE_REJ package when state was ALIVE\n");
            pthread_cancel(thread_comm); /* cancel thread reading from command line */
            unsuccefull_client_signup++;
            service();
            break;
        }else{
            failed_recived_ack++;
            if (debug_mode) {
                char msg[150];
                sprintf(msg, "DEBUG -> Have not received ALIVE_ACK. Current tries %d / %d\n\n",
                        failed_recived_ack, S);
                print_message(msg);
            }
        }

        if(failed_recived_ack == S){
            print_message("ERROR -> Maximum tries to contact server without valid ALIVE_ACK received reached\n");
            pthread_cancel(thread_comm);
            unsuccefull_client_signup++;
            service();
            break;
        }

    }
    return NULL; 
}

struct Package build_alive_inf_tosend_package(){
    struct Package alive_inf_to_sent_package;
    alive_inf_to_sent_package.pdu_type = get_packet_type("ALIVE_INF");
    strcpy(alive_inf_to_sent_package.id, client_data.id);
    strcpy(alive_inf_to_sent_package.mac_adress, client_data.mac_a);
    strcpy(alive_inf_to_sent_package.num_ale, server_data.num_ale);
    strcpy(alive_inf_to_sent_package.data, "");

    return alive_inf_to_sent_package;
}

bool check_received_package_ack_is_valid_udp(struct Package package){
    return (strcmp(server_data.id, package.id) == 0 &&
            strcmp(server_data.mac_a, package.mac_adress) == 0 &&
            strcmp(server_data.num_ale, package.num_ale) == 0);
}
void execute_send_cfg(){
    print_message("INFO-> Sending configuration file to server\n");

    if(access(network_dev_config_file_name, F_OK) == -1){
        char msg[200];
        sprintf(msg, "FAULT -> The access to the file %s failed \n", network_dev_config_file_name);
        print_message(msg);
        close(sockets_tcp.tcp_socket);
        return;

    }
    FILE *config_file = fopen(network_dev_config_file_name, "r");
    setup_tcp_socket();
    struct ConfigPackage send_file = build_Sent_file(config_file);
    send_package_tcp_to_server(send_file);



    struct ConfigPackage recived_package = receive_package_via_tcp(get_waiting_time_after_sent(W));


    if(sockets_tcp.tcp_timeout.tv_sec == 0){
        if (debug_mode){
            print_message("ERROR -> No answer received for send-cfg package\n"); 
        }
        close(sockets_tcp.tcp_socket);
        fclose(config_file);
        return;
    }else if(!check_received_package_ack_is_valid_tcp(recived_package,get_packet_type("SEND_ACK"))){
        if (debug_mode) { 
            print_message("ERROR -> Wrong package received for SEND_FILE package sent\n"); 
        }
        close(sockets_tcp.tcp_socket);
        fclose(config_file);
        return;
    }




    char line[150];
    while(fgets(line, 150, config_file)) {
        struct ConfigPackage send_data = build_Sent_file(line);
        send_package_tcp_to_server(send_data);
    }

    struct ConfigPackage send_end = build_send_end();
    send_package_tcp_to_server(send_end);
    close(sockets_tcp.tcp_socket);
    fclose(config_file);
    print_message("INFO -> Successfully ended sending configuration file to server\n");


}
void setup_tcp_socket(){
    struct hostent *host;


    host = gethostbyname(server_data.adress);
    if(!host){
        print_message("ERROR -> Can't find server!! \n");
    }

    sockets_tcp.tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(sockets_tcp.tcp_socket < 0){
        print_message("ERROR -> Could not create TCP socket\n");
        exit(1);
    }


    memset(&sockets_tcp.tcp_addr_server,0,sizeof(struct sockaddr_in));
    sockets_tcp.tcp_addr_server.sin_family  = AF_INET;
    sockets_tcp.tcp_addr_server.sin_addr.s_addr = (((struct in_addr *) host->h_addr_list[0])->s_addr);
    sockets_tcp.tcp_addr_server.sin_port = htons(sockets_tcp.tcp_port);


    if(connect(sockets_tcp.tcp_socket, (struct sockaddr *) &sockets_tcp.tcp_addr_server, sizeof(sockets_tcp.tcp_addr_server)) >0){
        print_message("ERROR -> Could not bind and connect to TCP socket\n");
        exit(1);
    }



}
struct ConfigPackage build_Sent_file(FILE *file){
    struct  ConfigPackage send_file;
    char data[150];
    long filesize;

    send_file.pdu_type = get_packet_type("SEND_FILE");
    strcpy(send_file.id, client_data.id);
    strcpy(send_file.mac_adress, client_data.mac_a);
    strcpy(send_file.num_ale, server_data.num_ale);



    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    printf(data, "%s,%li", network_dev_config_file_name, filesize);
    strcpy(send_file.data, data);

    return send_file;
}

void send_package_tcp_to_server(struct ConfigPackage package){
    int send_ = send(sockets_tcp.tcp_socket, &package, sizeof(package), 0);
    char msg[200];

    if(send_ < 0){
        print_message("ERROR -> Could not send package via TCP socket\n");

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

struct ConfigPackage receive_package_via_tcp(int timeout){
    fd_set rfds;
    char *buf = malloc(sizeof(struct ConfigPackage));
    struct ConfigPackage *recieve_package = malloc(sizeof(struct ConfigPackage));

    FD_ZERO(&rfds);
    FD_SET(sockets_tcp.tcp_socket, &rfds);
    sockets_tcp.tcp_timeout.tv_sec = timeout;

    if(select(sockets_tcp.tcp_socket + 1, &rfds, NULL, NULL, &sockets_tcp.tcp_timeout)){
        int rec = recv(sockets_tcp.tcp_socket, buf, sizeof(buf), 0);
        if(rec < 0){
            recieve_package = (struct ConfigPackage *) buf;
            if (debug_mode){
                char message[280];
                sprintf(message,
                        "DEBUG -> \t\t Received %s;\n"
                        "\t\t\t\t\t  Bytes:%lu,\n"
                        "\t\t\t\t\t  name:%s,\n "
                        "\t\t\t\t\t  mac:%s,\n"
                        "\t\t\t\t\t  rand num:%s,\n"
                        "\t\t\t\t\t  data:%s\n\n",
                        get_packet_string((unsigned char) (*recieve_package).pdu_type),
                        sizeof(*recieve_package), (*recieve_package).id,
                        (*recieve_package).mac_adress, (*recieve_package).num_ale,
                        (*recieve_package).data);
                print_message(message);
            }
        }
        
    }
    return *recieve_package;
    
}
bool check_received_package_ack_is_valid_tcp(struct ConfigPackage received, unsigned char expected_type){
    if(expected_type == get_packet_type("GET_END")){
        return( expected_type == received.pdu_type &&
                strcmp(server_data.id, received.id) == 0 &&
                strcmp(server_data.mac_a, received.mac_adress) == 0 &&
                strcmp(server_data.num_ale, received.num_ale) == 0 &&
                strcmp("", received.data) == 0);
    }


    return( expected_type == received.pdu_type &&
                strcmp(server_data.id, received.id) == 0 &&
                strcmp(server_data.mac_a, received.mac_adress) == 0 &&
                strcmp(server_data.num_ale, received.num_ale) == 0);
}

struct ConfigPackage build_send_end() {
    struct ConfigPackage send_end;

    /* start filling Package */
    send_end.pdu_type = get_packet_type("SEND_END");
    strcpy(send_end.id, client_data.id);
    strcpy(send_end.mac_adress, client_data.mac_a);
    strcpy(send_end.num_ale, server_data.num_ale);
    strcpy(send_end.data, "");

    return send_end;
}

void execute_get_cfg(){
    print_message("INFO -> Requested reception of configuration file from server\n");

    FILE *config_file = fopen(network_dev_config_file_name, "w");
    if(config_file == NULL){
        char msg[200];
        sprintf(msg, "ERROR -> File %s cannot be written\n", network_dev_config_file_name);
        print_message(msg);
        print_message("ERROR -> Unable to get configuration file from server\n");
        close(sockets_tcp.tcp_socket);
        return;
    }
    setup_tcp_socket();
    struct ConfigPackage get_package = build_get_confg(config_file);
    send_package_tcp_to_server(get_package);

    struct ConfigPackage recived_package = receive_package_via_tcp(get_waiting_time_after_sent(W));

    if(sockets_tcp.tcp_timeout.tv_sec == 0){
        if (debug_mode) {print_message("ERROR -> No answer received for GET_FILE package sent\n");}
        close(sockets_tcp.tcp_socket);
        fclose(config_file);
        return;
    } else if(!check_received_package_ack_is_valid_tcp(recived_package, get_packet_type("GET_ACK"))){
        if (debug_mode) { print_message("ERROR -> Wrong package received for GET_FILE package sent\n"); }
        close(sockets_tcp.tcp_socket);
        fclose(config_file);
        return;
    }

    while(recived_package.pdu_type != get_packet_type("GET_END")){
        recived_package = receive_package_via_tcp(get_waiting_time_after_sent(W));
        if(sockets_tcp.tcp_timeout.tv_sec == 0){
            if(debug_mode){
                char message[150];
                sprintf(message, "ERROR -> Have not received any data on TCP socket during %d seconds\n", W);
                print_message(message);
            }
            close(sockets_tcp.tcp_socket);
            fclose(config_file);
            return;
        } else if(!check_received_package_ack_is_valid_tcp(recived_package, get_packet_type("GET_DATA")) && 
                  !check_received_package_ack_is_valid_tcp(recived_package, get_packet_type("GET_END"))) {
            if(debug_mode){
                print_message("ERROR -> Wrong package GET_DATA or GET_END received from server\n");
            }
            close(sockets_tcp.tcp_socket);
            fclose(config_file);
            return;

        }
        fputs(recived_package.data, config_file);
    }
    close(sockets_tcp.tcp_socket);
    fclose(config_file);
    print_message("INFO -> Successfully ended reception of configuration file from server\n");
}

struct ConfigPackage build_get_confg(FILE *config_file){
    struct ConfigPackage get_file;
    char data[150];
    long filesize;


    get_file.pdu_type = get_packet_type("GET_FILE");
    strcpy(get_file.id, client_data.id);
    strcpy(get_file.mac_adress, client_data.mac_a);
    strcpy(get_file.num_ale, server_data.num_ale);


    fseek(config_file,0,SEEK_END);
    filesize = ftell(config_file);
    fseek(config_file,0,SEEK_SET);

    sprintf(data, "%s,%li", network_dev_config_file_name, filesize);
    strcpy(get_file.data, data);

    return get_file;
}