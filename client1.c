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

struct  ConfigPackage{
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


/*function declarations*/
void end(int signal);
void config_from_file(int argc, const char *argv[]);
void print_message(char *message);
void save_config(FILE *file);
void setup_udp_socket();
void service();
void change_client_state(char *newstate);
void register_to_server();


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
    exit(1);
}