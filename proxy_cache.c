//file name : proxy_cache.c
//date : 2022/05/27 ~
//os : ubuntu 16.04
//author : Kim Youngwook
//student id : 2018202039
//title : server of proxy server
//description : input = request from client or response from server
//				output = response to client or request to server
//				purpose = receive request from client -> send request to server -> receive response from server -> sent response (with semaphore and thread)
#include <stdio.h> //sprintf()
#include <string.h> //strcpy()
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> //inet_ntop
#include <unistd.h>
#include <stdlib.h> //malloc() and free()
#include <signal.h>
#include <sys/wait.h>

#include <netdb.h> //for DNS
#include <signal.h> //for SIGALRM

#include <sys/stat.h>
#include <fcntl.h> //open()
#include <openssl/sha.h> //SHA1()
#include <pwd.h>

#include <time.h> //for time functions
#include <dirent.h> //for dirent, DIR

#include <sys/ipc.h>
#include <sys/sem.h>
//for semaphore

#include <pthread.h>
//for thread

#define BUFFSIZE 1024
#define MAX 1024
#define PORTNO 39999

int fork_count = 0; //number of sub process
time_t begin_time; //time of main program's beginning
time_t end_time; //time of main program's end
time_t run_time; //time of main program's total run
char logfile[MAX]; //root of logfile
int hit_count = 0, miss_count = 0; //for counting hit and miss
//7 global variable

void* write_logfile(void* text);
void before_semaphore(int semid);
void after_semaphore(int semid);
void sig_alrm_handler(int signo);
void sig_int_handler(int signo);
char* getIPAddr(char* addr);
static void handler();
char* sha1_hash(char* input_url, char* hashed_url);
char* getHomeDir(char* home);
//9 function for main

//write_logfile
//intput : text
//output : none (MISS or HIT is appended to logfile)
//purpose : append MISS or HIT information into logfile by certain thread
void* write_logfile(void* text)
{
	int logfile_port = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0777); //make logfile with 777 permission when file isn't exist

	sleep(1); //take time to see effectiveness of semaphore
	write(logfile_port, (char*) text, strlen((char*)text)); //write information
	//write [Miss] or [HIT] string into logfile.txt
	//danger of race to logfile.txt

	close(logfile_port);
}

//before_semaphore
//intput : semid
//output : none (set semaphore)
//purpose : set semaphore to use certain child process exclusively
void before_semaphore(int semid)
{
	struct sembuf pbuf;
	pbuf.sem_num = 0;
	pbuf.sem_op = -1; //set
	pbuf.sem_flg = SEM_UNDO;

	if ((semop(semid, &pbuf, 1)) == -1)
	{
		perror("p : semop failed\n"); //set semaphore error
		exit(-20);
	}
}

//after_semaphore
//intput : semid
//output : none (reset semaphore)
//purpose : reset semaphore to make other child process use exclusively
void after_semaphore(int semid)
{
	struct sembuf vbuf;
	vbuf.sem_num = 0;
	vbuf.sem_op = 1; //reset
	vbuf.sem_flg = SEM_UNDO;

	if ((semop(semid, &vbuf, 1)) == -1)
	{
		perror("v : semop failed\n");  //reset semaphore error
		exit(-21);
	}
}

//sig_alrm_handler
//input : none (only child process can call this function)
//output : none (child process termination)
//purpose : child is killed if time takes more than 10 seconds to get request from real server
void sig_alrm_handler(int signo)
{
	printf("================= No Accept or No Response =================\n");
	abort(); //child process is killed
}

//sig_int_handler
//input : none (only parent process can call this function)
//output : none (parent process termination)
//purpose : write final line into log file then total program is terminated
void sig_int_handler(int signo)
{
	int port;
	char text[MAX] = { '\0' };

	end_time = time(NULL);
	run_time = end_time - begin_time; //get run_time

	strcat(logfile, "logfile.txt"); //logfile is home/logfile/logfile.txt
	port = open(logfile, O_APPEND | O_WRONLY, 0777);
	sprintf(text, "**SERVER** [Terminated] run time: %d sec. #sub process: %d", (int)run_time, fork_count);
	write(port, text, strlen(text)); //write termination information
	close(port);

	exit(0); //main process is terminated (end of program)
}

//getIPAddr
//input : URL(ex : "www.google.com")
//output : IP(ex : "142.250.199.100")
//purpose : convert URL into IP just like DNS server
char* getIPAddr(char* addr)
{
	struct hostent* hent;
	char* haddr;
	int len = strlen(addr);

	if ((hent = (struct hostent*) gethostbyname(addr)) != NULL)
	{
		haddr = inet_ntoa(*((struct in_addr *)hent->h_addr_list[0]));
	}

	return haddr;
}

//handler
//input : none (only parent process can call this function)
//output : none
//purpose : let parent process to wait for any child with WNOHANG option
static void handler()
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
		;
	}
}

//sha1_hash
//input : address of source string and destination string
//output : address of destination string
//purpose : source string -> hashing by SHA1 -> store into destination string(40 letters + '\0')
char* sha1_hash(char* input_url, char* hashed_url)
{
	unsigned char hashed_160bits[20];
	char hashed_hex[41]; //contain 40 letters + '\0'
	int i;

	SHA1(input_url, strlen(input_url), hashed_160bits); //first blank

	for (int i = 0; i < sizeof(hashed_160bits); i++) //sizeof(hashed_160bits) = 20
	{
		sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);
	}

	strcpy(hashed_url, hashed_hex); //second blank

	return hashed_url;
}

//getHimeDir
//input : address of source string
//output : address of source string (same as input)
//purpose : find home directory -> store into source string
char* getHomeDir(char* home)
{
	struct passwd* usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);

	return home; //home = home directory path
}

//main
//input, output, description is same as file comment
int main()
{
	begin_time = time(NULL); //record begin_time
	umask(0000); //remove umask

	int root_exist = 0; //for condition
	int url_cmp; //for strcmp

	int file_port; //for open()

	char url[MAX] = { '\0' }; //url input by user
	char url_hash[MAX] = { '\0' }; //hashed url

	char home[MAX] = { '\0' }; //address of home directory
	char root[MAX] = { '\0' }; //address of root directory
	char dir[MAX] = { '\0' }; //address of hashed directory
	char file_dir[MAX] = { '\0' }; //address of hashed file
	char file[38] = { '\0' }; //name of hashed file, contain 37 letters + '\0'
	char* p_url_hash_file; //for token
	//version 1 

	int hit = 0; //if hit == 0, it means miss.

	int logfile_dir_exist = 0;
	int logfile_exist = 0; //for condition
	int logfile_port; //for open()

	struct dirent* pFile; //pointer for file
	DIR* pDir; //pointer for directory

	time_t now;
	struct tm *ltp; //for measure time

	char text[MAX] = { '\0' }; //text for logfile

	getHomeDir(home); //get home
	strcat(root, home);
	strcat(root, "/cache/"); //root is home/cache/

	strcat(logfile, home);
	strcat(logfile, "/logfile/"); //logfile is home/logfile/

	//above : variable for algorithm

	int semid, i;
	union semun
	{
		int val;
		struct semid_ds *buf;
		unsigned short int* array;
	} arg;
	//data for semaphore

	if ((semid = semget((key_t)39999, 1, IPC_CREAT | 0666)) == -1) //key of semaphore is 39999
	{
		perror("semget failed\n"); //semaphore setting error
		exit(-11);
	}

	arg.val = 1;

	if ((semctl(semid, 0, SETVAL, arg)) == -1)
	{
		perror("semctl failed\n"); //semaphore setting error
		exit(-12);
	}

	//below : action for server

	struct sockaddr_in server_addr, client_addr;
	int socket_fd, client_fd;
	int len, len_out;
	//for socket

	int state;
	char buf[BUFFSIZE];
	char buf_2[BUFFSIZE];

	pid_t pid;
	pid_t childPID;
	//for fork

	int size = 0;

	if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("(Real Client-Proxy) Open stream socket failed\n"); //first error (socket failed)
		return -1;
	}

	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(PORTNO); //socket part

	if (bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) //bind part
	{
		printf("(Real Client-Proxy) bind local address failed\n"); //second error (bind failed)
		return -2;
	}

	listen(socket_fd, 5); //listen part
	signal(SIGCHLD, (void *)handler);

	signal(SIGINT, sig_int_handler); //check if interrupt occured

	while (1) //infinte loop until interrupted
	{
		char buf[BUFFSIZE];
		char response_header[BUFFSIZE] = { 0 };
		char response_message[BUFFSIZE] = { 0 };

		struct in_addr inet_client_address;

		char tmp[BUFFSIZE] = { 0 };
		char method[20] = { 0 };
		char url[BUFFSIZE] = { 0 };

		char* tok = NULL;

		len = sizeof(client_addr);
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len); //accept part

		if (client_fd < 0)
		{
			printf("(Real Client-Proxy) accept failed\n"); //third error (accept failed)
			return -3;
		}

		pid = fork(); //fork execute

		if (pid == -1) //fourth error (fork failed)
		{
			close(client_fd);
			close(socket_fd);
			continue;
		}

		fork_count++; //number of sub process increase

		if (pid == 0) //process for child
		{
			childPID = getpid();

			for (int i = 0; i < BUFFSIZE; i++)
				buf[i] = 0; //clear buffer

			inet_client_address.s_addr = client_addr.sin_addr.s_addr;

			for (int i = 0; i < sizeof(response_header); i++)
				response_header[i] = '\0';
			for (int i = 0; i < sizeof(response_message); i++)
				response_message[i] = '\0';

			//printf("[%s : %d] client was connected\n", inet_ntoa(inet_client_address), client_addr.sin_port); //information about connection
			read(client_fd, buf, BUFFSIZE); //receive request part (real client -> proxy)

			strcpy(tmp, buf);

			//puts("============================================================");
			//printf("Request from [%s : %d]\n", inet_ntoa(inet_client_address), client_addr.sin_port); //information about request
			//puts(buf);
			strcpy(buf_2, buf);
			//puts("============================================================");

			tok = strtok(tmp, " ");
			strcpy(method, tok);

			if (strcmp(method, "GET") == 0) //when method was GET
			{
				tok = strtok(NULL, " ");
				strcpy(url, tok);
			}

			char tok_url_1[BUFFSIZE] = { 0 }; //tokenized url
			char tok_url_2[BUFFSIZE] = { 0 }; //tokenized url

			char tok_url_IP[BUFFSIZE] = { 0 }; //tokenized url for get IP

			//url = http://www.xyz.com/123/456/789.html

			int i;
			for (i = 0; i < 7; i++)
				tok_url_1[i] = url[i]; //tok_url = http://

			int j;
			for (j = 0; url[i] != '\0'; i++, j++)
				tok_url_2[j] = url[i]; //tok_url_2 = www.xyz.com/123/456/789.html

			int k;
			for (k = 0; tok_url_2[k] != '/'; k++)
				tok_url_IP[k] = tok_url_2[k]; //tok_url_IP = www.xyz.com

			//below : source code from previous project

			if (logfile_dir_exist == 0) //when logfile is not exist
			{
				mkdir(logfile, S_IRWXU | S_IRWXG | S_IRWXO); //make logfile directory
				logfile_dir_exist = 1;
			}

			if (logfile_exist == 0) //when logfile.txt is not exist
			{
				strcat(logfile, "logfile.txt"); //logfile is home/logfile/logfile.txt
				logfile_port = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0777); //make logfile with 777 permission when file isn't exist
				logfile_exist = 1;
			}

			for (int i = 0; i < BUFFSIZE; i++)
				buf[i] = 0; //clear buffer

			if (root_exist == 0) //when root is not exist
			{
				mkdir(root, S_IRWXU | S_IRWXG | S_IRWXO); //make root directory
				root_exist = 1;
			}

			sha1_hash(tok_url_2, url_hash); //let hash is ABCDEF...XYZ

			strcpy(dir, root);

			i = 0;
			while (dir[i])
				i++;
			for (int j = 0; j < 3; j++)
				dir[i + j] = url_hash[j];
			//same as strcat_s(dir, 3, url_hash)

			strcat(dir, "/"); //dir is home/cache/ABC/

			p_url_hash_file = url_hash + 3;

			for (i = 0; i < 38; i++)
				file[i] = p_url_hash_file[i]; //file is DEF...XYZ
			//same as strcpy_s(file, 38, p_url_hash_file)

			mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO); //make url_hash directory with 777 permission

			strcpy(file_dir, dir);
			strcat(file_dir, file); //file_dir is home/cache/ABC/DEF...XYZ

			hit = 0; //let current state is miss

			pDir = opendir(dir); //open home/cache/ABC/
			if (pDir == NULL) //ABC directory not exist (miss)
				hit = 0;

			for (pFile = readdir(pDir); pFile; pFile = readdir(pDir))
			{
				int hit_check = strcmp(pFile->d_name, url_hash + 3);

				if (hit_check == 0) //DEF...XYZ file exist in ABC directory (hit)
				{
					hit = 1;
					break;
				}
			}

			closedir(pDir);

			time(&now); //now = time_t
			ltp = localtime(&now); //ltp = local tm

			if (hit == 1) //hit
			{
				printf("*PID# %d is waiting for the semaphore.\n", getpid());
				before_semaphore(semid); //set semaphore
				printf("*PID# %d is in the critical zone.\n", getpid());
				hit_count++;
				
				int err;
				void *tret;
				pthread_t tid;
				sprintf(text, "[HIT] ServerPID : %d | %.3s/%.37s - [%d/%d/%d, %02d:%02d:%02d]\n[HIT]%s\n", childPID, url_hash, url_hash + 3, 1900 + ltp->tm_year, 1 + ltp->tm_mon, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec, tok_url_2);

				err = pthread_create(&tid, NULL, write_logfile, (void*) text); //create thread
				printf("*PID# %d create the *TID# %lu.\n", getpid(), tid);
				if (err != 0) //create thread error
				{
					printf("pthread_create() error\n");
					exit(-31);
				}
				printf("*TID# %lu is exited.\n", tid);
				pthread_join(tid, &tret); //join thread

				printf("*PID# %d exited the critical zone.\n", getpid());
				after_semaphore(semid); //reset semaphore

				file_port = open(file_dir, O_RDONLY, 0777); //open for read content of response to real client
				for (int i = 0; i < BUFFSIZE; i++)
					buf[i] = 0; //clear buffer
				size = 0;
				//printf("\n========== PROXY -> CLIENT ==========\n");
				while (size = read(file_port, buf, BUFFSIZE) == BUFFSIZE)
				{
					//printf("\n========== BUF BEGIN ==========\n");
					//printf("%s", buf);
					//printf("\n========== BUF END ==========\n");
					write(client_fd, buf, BUFFSIZE); //send message
					for (int i = 0; i < BUFFSIZE; i++)
						buf[i] = 0; //clear buffer
					size = 0;
				}
				//printf("\n========== BUF BEGIN ==========\n");
				//printf("%s", buf);
				//printf("\n========== BUF END ==========\n");
				write(client_fd, buf, BUFFSIZE);
				for (int i = 0; i < BUFFSIZE; i++)
					buf[i] = 0; //clear buffer
				size = 0;
				close(file_port); //close for read content of response to real client
				//send respond part
			}

			else //miss
			{
				struct sockaddr_in server_addr_2; //socket between (proxy - real web server)
				int socket_fd_2, len_2;
				char haddr_2[] = "192.168.203.128"; //IP of proxy

				if ((socket_fd_2 = socket(PF_INET, SOCK_STREAM, 0)) < 0)
				{
					printf("(Proxy-Real Server) Create socket failed\n"); //first error
					return -1;
				}

				bzero((char *)&server_addr_2, sizeof(server_addr_2));

				server_addr_2.sin_family = AF_INET;
				inet_pton(AF_INET, getIPAddr(tok_url_IP), &(server_addr_2.sin_addr)); //IP of host
				server_addr_2.sin_port = htons(80); //socket part

				signal(SIGALRM, sig_alrm_handler);

				if (connect(socket_fd_2, (struct sockaddr *)&server_addr_2, sizeof(server_addr_2)) < 0) //connect part
				{
					printf("(Proxy-Real Server) Connect failed\n"); //second error
					return -2; //return -2 will be not executed because of alarm
				}

				printf("*PID# %d is waiting for the semaphore.\n", getpid());
				before_semaphore(semid); //set semaphore
				printf("*PID# %d is in the critical zone.\n", getpid());
				miss_count++;

				int err;
				void *tret;
				pthread_t tid;
				sprintf(text, "[MISS] ServerPID : %d | %s - [%d/%d/%d, %02d:%02d:%02d]\n", childPID, tok_url_2, 1900 + ltp->tm_year, 1 + ltp->tm_mon, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

				err = pthread_create(&tid, NULL, write_logfile, (void*) text); //create thread
				printf("*PID# %d create the *TID# %lu.\n", getpid(), tid);
				if (err != 0) //create thread error
				{
					printf("pthread_create() error\n");
					exit(-31);
				}
				printf("*TID# %lu is exited.\n", tid);
				pthread_join(tid, &tret); //join thread

				printf("*PID# %d exited the critical zone.\n", getpid());
				after_semaphore(semid); //reset semaphore

				if (write(socket_fd_2, buf_2, BUFFSIZE) > 0) //write part (proxy -> real server)
				{
					//now request has been sent to real server
					file_port = open(file_dir, O_WRONLY | O_CREAT, 0777); //open for write content of response from real server
					for (int i = 0; i < BUFFSIZE; i++)
						buf[i] = 0; //clear buffer
					len = 0;
					//printf("\n========== SERVER -> PROXY BEGIN ==========\n");
					while ((len = read(socket_fd_2, buf, 1)) == 1) //read part (real server -> proxy)
					{
						alarm(60); //set timer to 60
						//now respond has been received from real server
						//buf = respond from real server
						//printf("%s", buf);
						write(file_port, buf, 1); //write respond from real server to cache file (contains 1023 letters)
						for (int i = 0; i < 1; i++)
							buf[i] = 0; //clear buffer
						len = 0;
					}

					alarm(0); //reset timer
					//printf("%s", buf);
					//printf("\n========== SERVER -> PROXY END ==========\n");
					write(file_port, buf, 1); //write respond from real server to cache file (contains less than 1023 letters)
					for (int i = 0; i < 1; i++)
						buf[i] = 0; //clear buffer
					len = 0;
					close(file_port); //close for write content of response from real server
				}

				for (int i = 0; i < BUFFSIZE; i++)
					buf_2[i] = 0; //clear buffer

				file_port = open(file_dir, O_RDONLY, 0777); //open for read content of response to real client
				for (int i = 0; i < BUFFSIZE; i++)
					buf[i] = 0; //clear buffer
				size = 0;
				//printf("\n========== PROXY -> CLIENT ==========\n");
				while (size = read(file_port, buf, BUFFSIZE) == BUFFSIZE)
				{
					//printf("\n========== BUF BEGIN ==========\n");
					//printf("%s", buf);
					//printf("\n========== BUF END ==========\n");
					write(client_fd, buf, BUFFSIZE); //send message
					for (int i = 0; i < BUFFSIZE; i++)
						buf[i] = 0; //clear buffer
					size = 0;
				}
				//printf("\n========== BUF BEGIN ==========\n");
				//printf("%s", buf);
				//printf("\n========== BUF END ==========\n");
				write(client_fd, buf, BUFFSIZE);
				for (int i = 0; i < BUFFSIZE; i++)
					buf[i] = 0; //clear buffer
				size = 0;
				close(file_port); //close for read content of response to real client
				//send respond part
			}

			logfile_port = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0777); //make logfile with 777 permission when file isn't exist

			end_time = time(NULL);
			run_time = end_time - begin_time; //get run_time

			close(logfile_port);

			//above : source code from previous project

			//printf("[%s : %d] client was disconnected\n", inet_ntoa(inet_client_address), client_addr.sin_port); //information about disconnection
			close(client_fd);

			close(client_fd);
			exit(0); //end of child process
		}

		close(client_fd); //close part
	}

	close(socket_fd); //close part

	return 0;
}